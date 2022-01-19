#include "poly_interpolate.h"

//#include <chrono>
//#include <iostream>

#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ.h>
#include <NTL/tools.h>
#include <vector>
#include <cstdint>
#include <utility>

typedef std::uint32_t u32;

using namespace NTL;

static const ZZ mPrime256 = to_ZZ("115792089237316195423570985008687907853269984665640564039457584007913129640233");  //nextprime(2^256)

#define LEFT(X) (2*X+1)
#define RIGHT(X) (2*X+2)
#define PAPA(X) ((X-1)/2)

namespace
{

/*
void print_poly(ZZ_pX& P)
{
	long degree = deg(P);
	if (-1 == degree) {
		cout << "0";
		return;
	}
	for (long i = 0; i <= degree; i++) {
		cout << coeff(P, i);
		if (i == 1)
			cout << "X";
		else if (i > 1)
			cout << "X^" << i;
		if (i < degree) {
			cout << " + ";
		}
	}
}
*/

void build_tree(Vec<ZZ_pX>& tree, const Vec<ZZ_p>& points_x)
{
	size_t leaves_start = points_x.length() - 1;
	size_t tree_size = points_x.length() + leaves_start;
	tree.SetLength(tree_size);

	ZZ_p negated;

	//build all leaves
	for (u32 i = leaves_start; i < tree_size; i++) {
		NTL::negate(negated, points_x[i - leaves_start]); //get -xi
		SetCoeff(tree[i], 0, negated);
		SetCoeff(tree[i], 1, 1);
	}

	for (size_t i = leaves_start; i; i--) {
		size_t j = i - 1;
		tree[j] = tree[LEFT(j)] * tree[RIGHT(j)];
	}
}

void evaluate(const Vec<ZZ_pX>& tree, ZZ_pX P, Vec<ZZ_p>& points_y, size_t i)
{
	size_t leaves_start = points_y.length() - 1;
	if (i < leaves_start)
	{
		ZZ_pX L = P % tree[LEFT(i)];
		P %= tree[RIGHT(i)];

		evaluate(tree, std::move(L), points_y, LEFT(i));
		evaluate(tree, std::move(P), points_y, RIGHT(i));
	}
	else
		points_y[i - leaves_start] = coeff(P, 0);
}

void evaluate(const Vec<ZZ_pX>& tree, ZZ_pX P, Vec<ZZ_p>& points_y)
{
	P %= tree[0];
	evaluate(tree, std::move(P), points_y, 0);
}

ZZ_pX interpolate_zp(const Vec<ZZ_pX>& tree, const Vec<ZZ_p>& scale, const Vec<ZZ_p>& points_y, size_t i)
{
	size_t leaves_start = points_y.length() - 1;
	if (i < leaves_start)
		return interpolate_zp(tree, scale, points_y, LEFT(i)) * tree[RIGHT(i)] +
			interpolate_zp(tree, scale, points_y, RIGHT(i)) * tree[LEFT(i)];
	else
	{
		size_t y_index = i - leaves_start;
		ZZ_p inv_a;
		inv(inv_a, scale[y_index]); // inv_a = 1/a[y_index]
		ZZ_pX result;
		SetCoeff(result, 0, points_y[y_index] * inv_a);
		return result;
	}
}

ZZ_pX interpolate_zp(const Vec<ZZ_p>& points_x, const Vec<ZZ_p>& points_y)
{

	Vec<ZZ_pX> tree;
	build_tree(tree, points_x);

	ZZ_pX D;
	diff(D, tree[0]);

	Vec<ZZ_p> scale(INIT_SIZE, points_x.length());
	evaluate(tree, D, scale);

	return interpolate_zp(tree, scale, points_y, 0);
}

Vec<ZZ_p> load_points(const u_char (*points)[32], size_t num_points)
{
	Vec<ZZ_p> points_ZZp(INIT_SIZE, num_points);
	for (size_t i = 0; i < num_points; i++)
	{
		ZZ x;
		ZZFromBytes(x, points[i], 32);
		points_ZZp[i] = to_ZZ_p(x);
	}
	return points_ZZp;
}

void store_points(const Vec<ZZ_p>& points_ZZp, u_char (*points)[32])
{
	size_t num_points = points_ZZp.length();
	for (size_t i = 0; i < num_points; i++)
		BytesFromZZ(points[i], rep(points_ZZp[i]), 32);
}

ZZ_pX load_poly(const u_char *bytesArr, size_t numOfElements, size_t sizeOfElement) {
	//turn each byte to zz_p element in a vector

	Vec<ZZ_p> repFromBytes;
	repFromBytes.SetLength(numOfElements);

	for (size_t i = 0; i < numOfElements; i++) {
		ZZ zz;

		//translate the bytes into a ZZ element
		ZZFromBytes(zz, bytesArr + i*sizeOfElement, sizeOfElement);

		repFromBytes[i] = to_ZZ_p(zz);
	}

	//turn the vec_zzp to the polynomial
	return to_ZZ_pX(repFromBytes);
}

void store_poly(const ZZ_pX& poly, u_char *bytesArr, size_t numOfElements, size_t sizeOfElement) {
	//get the zz_p vector

	for (size_t i = 0; i < numOfElements; i++) {
		BytesFromZZ(bytesArr + i*sizeOfElement, rep(poly.rep[i]), sizeOfElement);
	}
}
}

void polynomial_interpolate(const u_char (*points_x)[32], const u_char (*points_y)[32], size_t num_points, u_char* poly)
{
	ZZ_p::init(mPrime256);

	Vec<ZZ_p> points_x_ZZp = load_points(points_x, num_points);
	Vec<ZZ_p> points_y_ZZp = load_points(points_y, num_points);

	ZZ_pX poly_ZZpX = interpolate_zp(points_x_ZZp, points_y_ZZp);

	store_poly(poly_ZZpX, poly, num_points, 32);
}

void polynomial_evaluate(const u_char (*points_x)[32], u_char (*points_y)[32], size_t num_points, const u_char* poly, size_t poly_coeffs)
{
	ZZ_p::init(mPrime256);

	Vec<ZZ_p> points_x_ZZp = load_points(points_x, num_points);

	Vec<ZZ_pX> tree;
	build_tree(tree, points_x_ZZp);

	ZZ_pX poly_px = load_poly(poly, poly_coeffs, 32);

	Vec<ZZ_p> points_y_ZZp(INIT_SIZE, num_points);
	evaluate(tree, poly_px, points_y_ZZp);

	store_points(points_y_ZZp, points_y);
}
