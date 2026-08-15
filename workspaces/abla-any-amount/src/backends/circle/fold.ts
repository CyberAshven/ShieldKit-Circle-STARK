import { add, inv, mul, sub, type M31El } from "./m31.ts";
import { negatePoint, projectPi, type CirclePoint } from "./group.ts";

/**
 * One Circle-FRI fold (2024/278 style).
 *
 * For evaluations f(P), f(P̄) where P̄ = (x, −y), and challenge λ:
 *   f'(π(P)) = (f(P)+f(P̄))/2 + λ · (f(P)−f(P̄)) / (2x)
 *
 * This is the first closed P2 piece (circle + one fold). It is not a verifier.
 */
export function foldPair(
  p: CirclePoint,
  fAtP: M31El,
  fAtConj: M31El,
  lambda: M31El,
): { domain: CirclePoint; value: M31El } {
  if (p.x === 0n) throw new Error("cannot fold at x=0");
  const twoInv = inv(2n);
  const even = mul(add(fAtP, fAtConj), twoInv);
  const odd = mul(sub(fAtP, fAtConj), twoInv);
  const oddOverX = mul(odd, inv(p.x));
  return {
    domain: projectPi(p),
    value: add(even, mul(lambda, oddOverX)),
  };
}

export function conjugate(p: CirclePoint): CirclePoint {
  return negatePoint(p);
}
