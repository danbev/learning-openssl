### Elliptic Curve Cryptography (EC)
The main motivation for using/developing EC, remember that we already have
algorithms that use the descrete logarithm problem. Well it turns out that with
EC we can have smaller operands but still the same amount of security. Remember
that the key lengths don't always correspond to the actual level of security due
to various attacks available. So we need to increase the sizes to still get the
same level of actual security. But with greater key sizes the computations
become more compute intensive and less efficient (like more power on devices
and CPU time). 

TODO: add table
```

```

We can do public exchange, encryption, and digital signatures with EC.

The idea is to find another cyclic group where the discrete logarithm problem
is difficult, preferrably more difficult than the cyclic group of Zp^*.

Lets start with the following polynomial which is a circle:
```
  x² + y² = r²
```
So we have a point on the circle `p(x, y)` and the radius is r.
```
0.707² + 0.707² = 1
```
Now, if we add cofficients to x and y we get an ellipse:
```
  ax² + by² = r²
```
The two examples above deal with real numbers.
For crypto we need to consider polynomials in Z_p.

Definition:
```
y² = x³ + ax + b mod p

We also need an imaginary point at infinity, where a,b ∈ Zp and 
4a³ + 27 b² != 0 mod p
```

Without using mod p we can visualize this (this is not possible when using
the modulo operation, the visual collapses), for example:
```
y² = x³ - 3x + 3
```
You can try this out at https://www.desmos.com/calculator/ialhd71we3

![Elliptic curve](./ec.png)
