#ifndef POLY_INTERPOLATE_H
#define POLY_INTERPOLATE_H

#ifdef __cplusplus
extern "C" {
#endif

// Poly bytes = poly_coeffs * 32. poly_coeffs = num_points
void polynomial_interpolate(const u_char (*points_x)[32], const u_char (*points_y)[32], size_t num_points, u_char* poly);

void polynomial_evaluate(const u_char (*points_x)[32], u_char (*points_y)[32], size_t num_points, const u_char* poly, size_t poly_coeffs)

#ifdef __cplusplus
}
#endif

#endif // POLY_INTERPOLATE_H
