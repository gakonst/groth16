//! An implementation of the [`Groth16`] zkSNARK.
//!
//! [`Groth16`]: https://eprint.iacr.org/2016/260.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_docs
)]
#![allow(clippy::many_single_char_names, clippy::op_ref)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate ark_std;

#[cfg(feature = "r1cs")]
#[macro_use]
extern crate derivative;

/// Reduce an R1CS instance to a *Quadratic Arithmetic Program* instance.
pub mod r1cs_to_qap;

/// Data structures used by the prover, verifier, and generator.
pub mod data_structures;

/// Generate public parameters for the Groth16 zkSNARK construction.
pub mod generator;

/// Create proofs for the Groth16 zkSNARK construction.
pub mod prover;

/// Verify proofs for the Groth16 zkSNARK construction.
pub mod verifier;

/// Constraints for the Groth16 verifier.
#[cfg(feature = "r1cs")]
pub mod constraints;

#[cfg(test)]
mod test;

pub use self::data_structures::*;
pub use self::{generator::*, prover::*, verifier::*};

use ark_crypto_primitives::snark::*;
use ark_ec::PairingEngine;
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef,
    OptimizationGoal, SynthesisError,
};
use ark_std::rand::RngCore;
use ark_std::{marker::PhantomData, vec::Vec};

pub struct InstantiatedGroth16<C, E: PairingEngine, QAP> {
    circuit: Option<C>,
    constraints_generated: bool,
    cs: ConstraintSystemRef<E::Fr>,
    pk: ProvingKey<E>,

    matrices: Option<ConstraintMatrices<E::Fr>>,
    qap: PhantomData<QAP>,
}

type D<F> = ark_poly::GeneralEvaluationDomain<F>;

impl<C: ConstraintSynthesizer<E::Fr>, E: PairingEngine, QAP: crate::r1cs_to_qap::R1CStoQAP>
    InstantiatedGroth16<C, E, QAP>
{
    pub fn new(circuit: C, pk: ProvingKey<E>) -> Self {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        Self {
            circuit: Some(circuit),
            constraints_generated: false,
            cs,
            matrices: None,
            pk,
            qap: PhantomData,
        }
    }

    pub fn generate_constraints(&mut self) -> Result<(), SynthesisError> {
        if self.constraints_generated {
            return Ok(())
        }

        if let Some(circuit) = self.circuit.take() {
            // Synthesize the circuit.
            let synthesis_time = start_timer!(|| "Constraint synthesis");
            circuit.generate_constraints(self.cs.clone())?;
            debug_assert!(self.cs.is_satisfied().unwrap());
            end_timer!(synthesis_time);

            let lc_time = start_timer!(|| "Inlining LCs");
            self.cs.finalize();
            end_timer!(lc_time);
        }

        Ok(())
    }

    pub fn matrices(&mut self) {
        if self.matrices.is_none() {
            self.matrices = self.cs.to_matrices();
        }
    }

    pub fn set_matrices(&mut self, matrices: ConstraintMatrices<E::Fr>) {
        self.matrices = Some(matrices);
    }

    /// to be used with new args for the circuit, but since the type is the same
    /// the constraints will be the same
    pub fn circuit(&mut self, circuit: C) {
        self.circuit = Some(circuit);
    }

    pub fn witness_map(&mut self) -> Result<Vec<E::Fr>, SynthesisError> {
        // calculate the matrices
        self.matrices();
        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = if let Some(ref matrices) = self.matrices {
            QAP::witness_map_with_matrices::<E::Fr, D<E::Fr>>(self.cs.clone(), matrices)?
        } else {
            QAP::witness_map::<E::Fr, D<E::Fr>>(self.cs.clone())?
        };
        end_timer!(witness_map_time);

        Ok(h)
    }

    fn prove(&mut self, r: E::Fr, s: E::Fr) -> ark_relations::r1cs::Result<Proof<E>> {
        // generate the constraints if necessary
        self.generate_constraints()?;
        let h = self.witness_map()?;
        create_proof_with_witness_map(h, &self.pk, self.cs.clone(), r, s)
    }
}

/// The SNARK of [[Groth16]](https://eprint.iacr.org/2016/260.pdf).
pub struct Groth16<E: PairingEngine> {
    e_phantom: PhantomData<E>,
}

impl<E: PairingEngine> SNARK<E::Fr> for Groth16<E> {
    type ProvingKey = ProvingKey<E>;
    type VerifyingKey = VerifyingKey<E>;
    type Proof = Proof<E>;
    type ProcessedVerifyingKey = PreparedVerifyingKey<E>;
    type Error = SynthesisError;

    fn circuit_specific_setup<C: ConstraintSynthesizer<E::Fr>, R: RngCore>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        let pk = generate_random_parameters::<E, C, R>(circuit, rng)?;
        let vk = pk.vk.clone();

        Ok((pk, vk))
    }

    fn prove<C: ConstraintSynthesizer<E::Fr>, R: RngCore>(
        pk: &Self::ProvingKey,
        circuit: C,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        create_random_proof::<E, _, _>(circuit, pk, rng)
    }

    fn process_vk(
        circuit_vk: &Self::VerifyingKey,
    ) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
        Ok(prepare_verifying_key(circuit_vk))
    }

    fn verify_with_processed_vk(
        circuit_pvk: &Self::ProcessedVerifyingKey,
        x: &[E::Fr],
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        Ok(verify_proof(&circuit_pvk, proof, &x)?)
    }
}

impl<E: PairingEngine> CircuitSpecificSetupSNARK<E::Fr> for Groth16<E> {}
