#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "./../doctest/doctest/doctest.h"
#include "../impl/serialization/serialization.hpp"

using namespace crypto;
using namespace crypto::fields;
using namespace crypto::curves;

std::string build_input(const std::string& data, const std::string& operation)
{
    int op_count = std::count(operation.begin(), operation.end(), ' ') + 1;
    return data + std::to_string(op_count) + " " + operation;
}

TEST_CASE("Fp 17")
{
    bInt p(17);
    std::vector<Fp> original = { Fp(5, p), Fp(16, p) };
    
    std::string data = Serializer::serialize_Fp(original, Serializer::BASE10);

    AnyStructure result = Serializer::deserialize(data);

    REQUIRE(std::holds_alternative<std::vector<Fp>>(result));

    auto restored = std::get<std::vector<Fp>>(result);
    
    CHECK(restored.size() == 2);
    
    CHECK(restored[0].get_value() == 5);
    CHECK(restored[1].get_value() == 16);
    
    CHECK(restored[0].get_modulus() == 17);
    CHECK(restored[1].get_modulus() == 17);
}

TEST_CASE("F2k 3")
{
    bInt poly("0x13"); // 10011 
    std::vector<F2k> original = { F2k(0xA, poly), F2k(0xF, poly) };

    std::string data = Serializer::serialize_F2k(original, Serializer::BASE16);

    AnyStructure result = Serializer::deserialize(data);

    REQUIRE(std::holds_alternative<std::vector<F2k>>(result));

    auto restored = std::get<std::vector<F2k>>(result);
    
    CHECK(restored.size() == 2);
    CHECK(restored[0].get_value() == 0xA);
    CHECK(restored[1].get_value() == 0xF);
    CHECK(restored[0].get_modulus() == poly);
}

TEST_CASE("Fpk 7 3")
{
    bInt p(7);
    std::vector<Fp> temp_vec = { Fp(1, p), Fp(0, p), Fp(1, p) };
    auto poly_ptr = std::make_shared<std::vector<Fp>>(temp_vec);
    std::vector<Fpk> original;
    original.push_back(Fpk({2, 3}, poly_ptr));

    std::string data = Serializer::serialize_Fpk(original, Serializer::BASE10);

    AnyStructure result = Serializer::deserialize(data);

    REQUIRE(std::holds_alternative<std::vector<Fpk>>(result));

    auto restored = std::get<std::vector<Fpk>>(result);

    CHECK(restored.size() == 1);
    
    CHECK(restored[0].coeffs.size() >= 2);
    CHECK(restored[0].coeffs[0].get_value() == 2);
    CHECK(restored[0].coeffs[1].get_value() == 3);

    CHECK(restored[0].irreducible_poly->size() == 3); 
    CHECK((*restored[0].irreducible_poly)[0].get_value() == 1); 
}

TEST_CASE("Fpk 7 3") 
{
    bInt p(7);
    std::vector<Fp> temp_vec = { Fp(1, p), Fp(0, p), Fp(1, p) };
    auto poly_ptr = std::make_shared<std::vector<Fp>>(temp_vec);
    std::vector<Fpk> original;
    original.push_back(Fpk({2, 3}, poly_ptr));
    original.push_back(Fpk({2, 3}, poly_ptr));

    std::string data = Serializer::serialize_Fpk(original, Serializer::BASE10);
    std::string input_with_onp = build_input(data, "0 1 +");

    auto [structure, result] = Serializer::deserializeWithAction(input_with_onp);

    REQUIRE(std::holds_alternative<Fpk>(result)); 

    auto restored_val = std::get<Fpk>(result);

    CHECK(restored_val.coeffs[0].get_value() == 4);
    CHECK(restored_val.coeffs[1].get_value() == 6);

    REQUIRE(std::holds_alternative<std::vector<Fpk>>(structure));
    auto& original_vec = std::get<std::vector<Fpk>>(structure);
    CHECK(original_vec.size() == 2);
}

TEST_CASE("E(F2k) dodawanie")
{
    bInt poly("0xB");
    F2k a(1, poly);
    F2k b(1, poly);
    EllipticCurveBinary curve(a, b);
    
    std::string input = "1 5 B 1 1 2 2 4 2 4 3 0 1 +";

    auto [structure, opResult] = Serializer::deserializeWithAction(input);

    REQUIRE(std::holds_alternative<std::pair<EllipticCurveBinary, std::vector<PointF2k>>>(structure));
    REQUIRE(std::holds_alternative<PointF2k>(opResult));

    PointF2k resultPoint = std::get<PointF2k>(opResult);
    
    PointF2k expected = curve.add(PointF2k(F2k(2, poly), F2k(4, poly)), 
                                  PointF2k(F2k(2, poly), F2k(4, poly)));
    
    CHECK(resultPoint.x.get_value() == expected.x.get_value());
    CHECK(resultPoint.y.get_value() == expected.y.get_value());
}

TEST_CASE("##")
{
    std::string input = "1 5 B 1 1 2 2 4 # # 3 0 1 +";

    auto [structure, opResult] = Serializer::deserializeWithAction(input);

    REQUIRE(std::holds_alternative<PointF2k>(opResult));
    PointF2k res = std::get<PointF2k>(opResult);
    
    CHECK(res.x.get_value() == 2);
    CHECK(res.y.get_value() == 4);
    CHECK(res.is_infinity == false);
}

TEST_CASE("Fp")
{
    bInt p(31);
    Fp a(10, p);
    Fp b(25, p);
    std::vector<Fp> original = { a, b };

    std::string data = Serializer::serialize_Fp(original, Serializer::BASE10);
    
    std::string input_with_onp = build_input(data, "0 1 +");

    auto [structure, opResult] = Serializer::deserializeWithAction(input_with_onp);

    Fp expected = a + b; 
    
    REQUIRE(std::holds_alternative<Fp>(opResult));
    Fp result = std::get<Fp>(opResult);
    
    CHECK(result.get_value() == expected.get_value());
    CHECK(result.get_value() == 4);
}

TEST_CASE("Fp")
{
    bInt p(17);
    Fp a(5, p);
    Fp b(4, p);
    std::vector<Fp> original = { a, b };

    std::string data = Serializer::serialize_Fp(original, Serializer::BASE10);
    
    std::string input_with_onp = build_input(data, "0 1 * 0 -");

    auto [structure, opResult] = Serializer::deserializeWithAction(input_with_onp);

    Fp expected = (a * b) - a; 
    
    REQUIRE(std::holds_alternative<Fp>(opResult));
    CHECK(std::get<Fp>(opResult).get_value() == expected.get_value());
}

TEST_CASE("E(F2k)")
{
    bInt poly("0x13"); 
    F2k curve_a(1, poly);
    F2k curve_b(0xA, poly);
    EllipticCurveBinary curve(curve_a, curve_b);

    F2k x1(0x2, poly), y1(0x4, poly);
    F2k x2(0xC, poly), y2(0x8, poly);
    PointF2k P(x1, y1);
    PointF2k Q(x2, y2);
    
    std::vector<PointF2k> points = { P, Q };

    std::string data = Serializer::serialize_CurveBinary(curve, points, Serializer::BASE16);
    
    std::string input_with_onp = build_input(data, "0 1 +");

    auto [structure, opResult] = Serializer::deserializeWithAction(input_with_onp);

    PointF2k expected = curve.add(P, Q);
    
    REQUIRE(std::holds_alternative<PointF2k>(opResult));
    PointF2k result = std::get<PointF2k>(opResult);
    
    CHECK(result.x.get_value() == expected.x.get_value());
    CHECK(result.y.get_value() == expected.y.get_value());
    CHECK(result.is_infinity == expected.is_infinity);
}

TEST_CASE("E(Fpk)")
{
    bInt p(13);
    auto poly_ptr = std::make_shared<std::vector<Fp>>(std::vector<Fp>{Fp(1, p), Fp(0, p), Fp(1, p)}); 
    
    Fpk a({1}, poly_ptr);
    Fpk b({1}, poly_ptr);
    EllipticCurve curve(a, b);

    Fpk x({1, 2}, poly_ptr);
    Fpk y({3, 4}, poly_ptr);
    Point P(x, y);
    
    std::vector<Point> points = { P, P };

    std::string data = Serializer::serialize_Curve(curve, points, Serializer::BASE10);
    std::string input_with_onp = build_input(data, "0 1 +");

    auto [structure, opResult] = Serializer::deserializeWithAction(input_with_onp);

    Point expected = curve.add(P, P);
    
    REQUIRE(std::holds_alternative<Point>(opResult));
    Point result = std::get<Point>(opResult);

    CHECK(result == expected);
    
    CHECK(result.x.coeffs[0].get_value() == expected.x.coeffs[0].get_value());
}

TEST_CASE("Fpk, 13, 2")
{
    std::string raw_data = "0 3 13 2 2 0 1 0 0 1 0 3 0 1 0 1 0 0 1 0 1 0 0 0 ";
    
    std::string onp_expression = "0 2 *";
    
    std::string full_input = build_input(raw_data, onp_expression);

    auto [structure, result] = Serializer::deserializeWithAction(full_input);

    REQUIRE(std::holds_alternative<std::pair<EllipticCurve, std::vector<Point>>>(structure));
    auto& [curve, points] = std::get<std::pair<EllipticCurve, std::vector<Point>>>(structure);
    
    CHECK(points.size() == 3);
    CHECK(curve.a.coeffs[0].get_value() == 0);
    CHECK(curve.b.coeffs[0].get_value() == 1);

    REQUIRE(std::holds_alternative<Point>(result));
    Point res_point = std::get<Point>(result);

    CHECK(res_point.x.coeffs[0].get_value() == 1);
    CHECK(res_point.y.coeffs[0].get_value() == 0);
    CHECK(res_point.is_infinity == false);
}

TEST_CASE("main")
{
    std::vector<std::string> test_cases = {
        "0 1 31 2 10 25 3 0 1 +",
        "0 2 19 2 10 15 3 0 1 +",
        "0 1 17 2 5 4 5 0 1 * 0 -",
        "0 0 7 2 1 0 1 2 2 3 2 3 3 0 1 +",
        "0 1 13 3 1 5 12 8 0 1 + 2 ! + 1 ^"
    };

    for (const auto& input : test_cases)
    {
        auto [structure, opResult] = Serializer::deserializeWithAction(input);
        auto tokens = Serializer::split(input);
        int typeInt = std::stoi(tokens[1]);
        Serializer::Type type = static_cast<Serializer::Type>(typeInt);

        switch (type)
        {
            case Serializer::T_FP:
            {
                auto res = std::get<Fp>(opResult);
                std::cout << "Fp(" << res.get_value() << ")" << std::endl;
                break;
            }
            case Serializer::T_F2K:
            {
                auto res = std::get<F2k>(opResult);
                std::cout << "F2k(" << res.get_value() << ")"  << std::endl;
                break;
            }
            case Serializer::T_FPK:
            {
                auto res = std::get<Fpk>(opResult);
                std::cout << "Fpk[";
                for (const auto& c : res.coeffs) std::cout << c.get_value() << " ";
                std::cout << "]" << std::endl;
                break;
            }
            case Serializer::T_E_F2K:
            {
                auto res = std::get<PointF2k>(opResult);
                if (res.is_infinity) 
                {
                    std::cout << "INF";
                }
                else 
                {
                    std::cout << "PointFpk(x=";
                    std::cout << res.x.get_value();
                    
                    std::cout << ", y=";
                    std::cout << res.y.get_value();
                    
                    std::cout << ")" << std::endl;
                }
                break;
            }
            case Serializer::T_E_FPK:
            {
                auto res = std::get<Point>(opResult);
                if (res.is_infinity) 
                {
                    std::cout << "PointFpk: INF";
                }
                else 
                {
                    std::cout << "PointFpk(x=";
                    if (!res.x.coeffs.empty()) std::cout << res.x.coeffs[0].get_value();
                    else std::cout << "0";
                    
                    std::cout << ", y=";
                    if (!res.y.coeffs.empty()) std::cout << res.y.coeffs[0].get_value();
                    else std::cout << "0";
                    std::cout << ")" << std::endl;
                }
                break;
            }
            default:
            {
                break;
            }
        }

    }
}