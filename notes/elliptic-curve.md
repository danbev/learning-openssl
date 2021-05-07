### Elliptic Curve Cryptography (EC)

The main motivation for using/developing EC, remember that we already have
algorithms that use the discrete logarithm problem. Well it turns out that with
EC we can have smaller operands but still the same amount of security. Remember
that the key lenghts don't always correspond to the actual level of security due
to various attacks available. So we need to increase the sizes to still get the
same level of actual security. But with greater key sizes the computations
become more compute intensive and less efficient (like more power on devices
and CPU time). 

TODO: add table
```
```

We can do public key exchange, encryption, and digital signatures with EC.

The idea is to find another cyclic group where the discrete logarithm problem
is difficult, preferrably more difficult than the cyclic group of Zp^*.

Lets start with the following polynomial, which is a circle:
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

### Definition
```
y² = x³ + ax + b mod p

We also need an imaginary point at infinity, where a,b ∈ Zp and 
4a³ + 27 b² != 0 mod p  (these curves cannot be used in crypto)
```

Without using mod p we can visualize this (this is not possible when using
the modulo operation, the visual collapses), for example:
```
y² = x³ - 3x + 3
```
You can try this out at https://www.desmos.com/calculator/ialhd71we3

![Elliptic curve](./ec.png)

And get the value of y then we square:
```
y² = x³ + ax + b
      ____________
y  = √ x³ + ax + b
```

Just to get a feel for this lets plug in x=1:
```
x = 1
y² = 1³ - 3*1 + 3
y² = 1 - 3 + 3
y² = -2    + 3
y² = 1
y  = √1
y  = +- 1
```
And if we look at the graph we can see that (1, 1) and (1, -1) are both valid
points on the curve. The +- shows the symmetry of the curve, the points are
reflected.

Now, we need a cyclic group for the descrete logarithm problem.
The set of `group elements` are the `points` on the curve and we need to be able
to compute with these elements, much like we computed with integers earlier.
This is the group operation and previously we used multiplication.

We need to be able to `add` points together which is the group operation.

### Group operation
This is the add points, the group elememts, on the curve.

So how do we add points:
```
P =  (point on the curve)
Q =  (point on the curve)

P + Q = ?
```
We can visualize this (again without mod p). Draw a line between from the first
point to the second and let it extend through the second point and continue. It
will intersect with the curve at some point when we do this. Now, remember we
mentioned that the curve is symmetric, so we reflect (multiple by -1?) which
gives as the point R. So R = P + Q. 
This is the definition of the group operation.

Now, think about the point P and what if we want to add the same point with
itself, like 1 + 1 = 2. We can't draw a line from the point to itself, there
will be no intersect point that we can reflect.

Now, there are two different cases we have to consider
```
1) Point addition (what was described above)
   R = P + Q

2) Point doubling
   For this we have to take the tagent and see where it intersects with the
   curve, and then reflect that point.
```

So that was a nice visual but how do we actually compute these points.
Well we have to compute the line between the two points and we know the two
points (just to make that clear):
```
P = (x₁, y₁)
Q = (x₂, y₂)

y = sx + m

Where s is the slope we can get by taking:
 (y₂ - y₁)
 --------- = s
 (x₂ - x₁) 

So then would become:
    (y₂ - y₁)
y = --------- x + m
    (x₂ - y1)


Now we need to find the intersection with the curve after finding the line.
E: y² = x³ + ax + b
l: y  = sx + m

l = E
(sx + m)²            = x³ + ax + b
(sx + m)(sx + m)     = x³ + ax + b

sx² + sxm + sxm + m² = x³ + ax + b
s²*x² + 2smx + m²    = x³ + ax + b
```
So we can see that we have an equation with degree 3 so we have 3 solutions,
x₁, x₂, and x₃.
```
x₁ is the x value of point P(x₁, y₁)
x₂ is the x value of point Q(x₂, y₂)
x₃ is the x value of the intersect point R(x₃, y₃)

x₃ = x² - x₁ - x₂ mod p
y₃ = x(x₁ - x₃) - y₁ mod p
```

```
 y₂ - y₁
 -------  mod p     -> (y₂ - y₁)(x₂ - x₁)⁻¹ mod p
 x₂ - x₁
```

To be a group we need to fulfill the requirements that the group operation
is closed, associative. 
There also has to be an identity element such that a + 1 = 1 + a = a. What is
this identity value of this group?  
So P + (some point) = P
It turns out that there is no point that we can calculate using the above steps
and get this 0/NUll point, instead one has been defined.
This is "point at infinity" which uses the symbol ó.
```
P + ó = P
```
```
-P  of P(x, y) is -P = (x, -y)
```

### EC Discrete Logarithm Problem (EC-DLP)
Elliptic curve as a cyclic group (not all curves form a cyclic group:
```
E: y² = x³ +2x + 2 mod 17
```
For the group to be cyclic we need a generator/primitive element which can
generate points on the curve. An example of a primitive element is:
```
Primitive Element P = (5, 1)    // (x, y)

2P  = (5, 1) + (5, 1)  = (formula from above) = (6, 3)
3P  = 2P + P           = (formula from above) = (10, 6)
...
18P = 17P + P          = (formula from above) = (5, 16)
```
Notice that for 18P we have the same x coordinate 5 as the primitive element,
and 16 is the inverse mod p of 1:
18P =(5, 16) = (5, -1)
__wip__


