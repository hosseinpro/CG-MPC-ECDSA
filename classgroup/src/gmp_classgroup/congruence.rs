use super::mpz::Mpz;
use super::mpz_ops;

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct CongruenceContext {
    pub g: Mpz,
    pub d: Mpz,
    pub q: Mpz,
    pub r: Mpz,
}

impl Default for CongruenceContext {
    fn default() -> Self {
        Self {
            g: Mpz::new(),
            d: Mpz::new(),
            q: Mpz::new(),
            r: Mpz::new(),
        }
    }
}

impl CongruenceContext {
    /// Solves `a*x = b (mod m)`, storing `x` in `mu`
    ///
    /// This function may clobber any or all of `self`’s member variables.
    ///
    /// # Panics
    ///
    /// Panics if the congruence could not be solved.
    pub fn solve_linear_congruence(
        &mut self,
        mu: &mut Mpz,
        v: Option<&mut Mpz>,
        a: &Mpz,
        b: &Mpz,
        m: &Mpz,
    ) {
        mpz_ops::mpz_gcdext(&mut self.g, &mut self.d, mu, a, m);
        if cfg!(test) {
            println!(
                "g = {}, d = {}, e = {}, a = {}, m = {}",
                self.g, self.d, mu, a, m
            );
        }
        if cfg!(debug_assertions) {
            mpz_ops::mpz_fdiv_qr(&mut self.q, &mut self.r, b, &self.g);
            debug_assert!(self.r.is_zero(), "Could not solve the congruence ― did you pass a non-prime or a positive number to the command line tool?!");
        } else {
            mpz_ops::mpz_divexact(&mut self.q, b, &self.g)
        }
        mpz_ops::mpz_mul(&mut self.r, &self.q, &self.d);
        mpz_ops::mpz_tdiv_r(mu, &self.r, m);
        if let Some(v) = v {
            if cfg!(debug_assertions) {
                mpz_ops::mpz_fdiv_qr(v, &mut self.r, &m, &self.g);
                debug_assert!(self.r.is_zero(), "Could not solve the congruence ― did you pass a non-prime or a positive number to the command line tool?!");
            } else {
                mpz_ops::mpz_divexact(v, &m, &self.g)
            }
        }
    }
}
