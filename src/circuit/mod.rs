use bellman::{pairing::Engine, Circuit, ConstraintSystem, Field, SynthesisError, Variable};

#[derive(Clone)]
pub struct Bit {
    var: Variable,
    value: Option<bool>,
}

impl Bit {
    fn alloc<E, CS>(
        value: Option<bool>,
        cs: &mut CS,
        zero: Variable,
    ) -> Result<Self, SynthesisError>
    where
        E: Engine,
        CS: ConstraintSystem<E>,
    {
        let var = cs.alloc(
            || "bit",
            || match value {
                Some(true) => Ok(E::Fr::one()),
                Some(false) => Ok(E::Fr::zero()),
                None => Err(SynthesisError::AssignmentMissing),
            },
        )?;

        cs.enforce(
            || "bit must be 0 or 1",
            |la| la + CS::one() - var,
            |lb| lb + var,
            |lc| lc + zero,
        );

        Ok(Self { var, value })
    }

    fn inputize<E, CS>(&self, cs: &mut CS) -> Result<(), SynthesisError>
    where
        E: Engine,
        CS: ConstraintSystem<E>,
    {
        let input = cs.alloc_input(
            || "input variable",
            || match self.value {
                Some(true) => Ok(E::Fr::one()),
                Some(false) => Ok(E::Fr::zero()),
                None => Err(SynthesisError::AssignmentMissing),
            },
        )?;

        cs.enforce(
            || "enforce input is correct",
            |la| la + input,
            |lb| lb + CS::one(),
            |lc| lc + self.var,
        );

        Ok(())
    }

    fn xor<E, CS>(&self, other: &Self, cs: &mut CS) -> Result<Self, SynthesisError>
    where
        E: Engine,
        CS: ConstraintSystem<E>,
    {
        let new_var = cs.alloc(
            || "bit",
            || {
                let val = self.value.ok_or(SynthesisError::AssignmentMissing)?;
                let other = other.value.ok_or(SynthesisError::AssignmentMissing)?;
                let new_val = val ^ other;

                if new_val {
                    Ok(E::Fr::one())
                } else {
                    Ok(E::Fr::zero())
                }
            },
        )?;

        cs.enforce(
            || "must be conform xor operation",
            |la| la + self.var + self.var,
            |lb| lb + other.var,
            |lc| lc + self.var + other.var - new_var,
        );

        let new_val = match (self.value, other.value) {
            (Some(val), Some(other)) => Some(val ^ other),
            _ => None,
        };

        Ok(Self {
            var: new_var,
            value: new_val,
        })
    }
}

/// Circuit a xor b = c
#[derive(Clone)]
pub struct XorCircuit {
    pub a: Option<bool>,
    pub b: Option<bool>,
    pub c: Option<bool>,
}

impl<E: Engine> Circuit<E> for XorCircuit {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let zero = cs.alloc(|| "zero", || Ok(E::Fr::zero()))?;

        let a = Bit::alloc(self.a, cs, zero)?;
        a.inputize(cs)?;

        let b = Bit::alloc(self.b, cs, zero)?;
        b.inputize(cs)?;

        let actual_c = a.xor(&b, cs)?;
        let expected_c = Bit::alloc(self.c, cs, zero)?;

        cs.enforce(
            || "actual_c must equal expected_c",
            |la| la + actual_c.var,
            |lb| lb + CS::one(),
            |lc| lc + expected_c.var,
        );

        Ok(())
    }
}
