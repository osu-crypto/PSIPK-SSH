#ifndef POLY_INTERPOLATE_H
#define POLY_INTERPOLATE_H

#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

// Poly bytes = poly_coeffs * 32. poly_coeffs = num_points
void polynomial_interpolate(const unsigned char (*points_x)[32], const unsigned char (*points_y)[32], size_t num_points, unsigned char* poly);

void polynomial_evaluate(const unsigned char (*points_x)[32], unsigned char (*points_y)[32], size_t num_points, const unsigned char* poly, size_t poly_coeffs);

#ifdef __cplusplus
}
#endif

#endif // POLY_INTERPOLATE_H
