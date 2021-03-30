use bellman::{pairing::Engine, Circuit, ConstraintSystem, Field, SynthesisError, Variable};

#[derive(Clone)]
pub struct Bit {
    var: Variable,
    value: bool,
}

impl Bit {
    fn alloc<E, CS>(value: bool, cs: &mut CS, zero: Variable) -> Result<Self, SynthesisError>
    where
        E: Engine,
        CS: ConstraintSystem<E>,
    {
        let var = cs.alloc(
            || "bit",
            || {
                if value {
                    Ok(E::Fr::one())
                } else {
                    Ok(E::Fr::zero())
                }
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
            || {
                if self.value {
                    Ok(E::Fr::one())
                } else {
                    Ok(E::Fr::zero())
                }
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
        let new_val = self.value ^ other.value;
        let new_var = cs.alloc(
            || "bit",
            || {
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

        Ok(Self {
            var: new_var,
            value: new_val,
        })
    }
}

/// Circuit a xor b = c
#[derive(Clone)]
pub struct XorCircuit {
    pub a: bool,
    pub b: bool,
    pub c: bool,
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
