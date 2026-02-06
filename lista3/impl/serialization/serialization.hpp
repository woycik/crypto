#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <variant>
#include <stack>
#include <utility>
#include <memory>
#include "../types.hpp"
#include "../fields/fp.hpp"
#include "../fields/f2k.hpp"
#include "../fields/fpk.hpp"
#include "../curves/fpkCurves.hpp" 
#include "../curves/f2kCurves.hpp"
#include "../curves/fpCurves.hpp"

using namespace crypto;
using namespace crypto::fields;
using namespace crypto::curves;

using AnyStructure = std::variant<
    std::monostate,                                     
    std::vector<Fp>,                    
    std::vector<F2k>,                   
    std::vector<Fpk>,                   
    std::pair<EllipticCurveFpk, std::vector<crypto::curves::PointFpk>>,
    std::pair<EllipticCurveBinary, std::vector<crypto::curves::PointF2k>>,
    std::pair<EllipticCurve, std::vector<crypto::curves::PointFp>>
>;

using OperationResult = std::variant<std::monostate, Fp, F2k, Fpk, PointFpk, PointF2k, PointFp>;

class Serializer {
public:
    enum Base { BASE10 = 0, BASE16 = 1, BASE64 = 2 };
    enum Type { 
        T_FPK = 0, 
        T_FP = 1, 
        T_F2K = 2, 
        T_E_FPK = 3, 
        T_E_FP = 4, 
        T_E_F2K = 5 
    };

    static std::string bint_to_str(const bInt& val, Base base);
    static bInt str_to_bint(const std::string& str, Base base);
    static std::vector<std::string> split(const std::string& s);

    static std::string serialize_Fp(const std::vector<Fp>& elements, Base base);
    static std::string serialize_F2k(const std::vector<F2k>& elements, Base base);
    static std::string serialize_Fpk(const std::vector<Fpk>& elements, Base base);
    static std::string serialize_Curve(const EllipticCurveFpk& curve, const std::vector<PointFpk>& points, Base base);
    static std::string serialize_CurveFp(const EllipticCurve& curve, const std::vector<PointFp>& points, Base base);
    static std::string serialize_CurveBinary(const EllipticCurveBinary& curve, const std::vector<PointF2k>& points, Base base);

    static AnyStructure deserialize(const std::string& raw);
    static std::pair<AnyStructure, OperationResult> deserializeWithAction(const std::string& raw);

private:
    static OperationResult executeONP(const AnyStructure& structure, const std::vector<std::string>& ops, Base base);
    
    static std::vector<Fp> deserialize_Fp(const std::string& raw);
    static std::vector<F2k> deserialize_F2k(const std::string& raw);
    static std::vector<Fpk> deserialize_Fpk(const std::string& raw);
    static std::pair<EllipticCurveBinary, std::vector<PointF2k>> deserialize_CurveBinary(const std::string& raw);
    static std::pair<EllipticCurve, std::vector<PointFp>> deserialize_CurveFp(const std::string& raw);
    static std::pair<EllipticCurveFpk, std::vector<PointFpk>> deserialize_Curve(const std::string& raw);
};