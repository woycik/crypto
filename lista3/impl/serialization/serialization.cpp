#include "serialization.hpp"

std::string Serializer::bint_to_str(const bInt& val, Base base) {
    std::stringstream ss;
    if (base == BASE16) ss << std::hex;
    ss << val;
    std::string s = ss.str();
    if (s.rfind("0x", 0) == 0) s = s.substr(2);
    return s;
}

bInt Serializer::str_to_bint(const std::string& str, Base base) {
    if (str.empty()) return 0;
    switch (base) {
        case BASE10: return bInt(str);
        case BASE16: return bInt("0x" + str);
        default: return 0;
    }
}

std::vector<std::string> Serializer::split(const std::string& s) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);

    while (tokenStream >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

std::string Serializer::serialize_Fp(const std::vector<Fp>& elements, Base base) {
    if (elements.empty()) return "";
    std::stringstream ss;

    ss << (int)base << " " << (int)T_FP << " " << bint_to_str(elements[0].get_modulus(), base) << " " << elements.size() << " ";
    for (const auto& el : elements) ss << bint_to_str(el.get_value(), base) << " ";

    return ss.str();
}

std::string Serializer::serialize_F2k(const std::vector<F2k>& elements, Base base) {
    if (elements.empty()) return "";
    std::stringstream ss;

    ss << (int)base << " " << (int)T_F2K << " " << bint_to_str(elements[0].get_modulus(), base) << " " << elements.size() << " ";
    for (const auto el : elements) ss << bint_to_str(el.get_value(), base) << " ";

    return ss.str();
}

std::string Serializer::serialize_Fpk(const std::vector<Fpk>& elements, Base base) {
    if (elements.empty()) return "";
    std::stringstream ss;

    const Fpk& proto = elements[0];
    bInt p = proto.get_p();
    int k = proto.irreducible_poly->size() - 1;

    ss << (int)base << " " << (int)T_FPK << " " << bint_to_str(p, base) << " " << k << " ";
    for (const auto& coeff : *proto.irreducible_poly) ss << bint_to_str(coeff.get_value(), base) << " ";
    ss << elements.size() << " ";

    for (const auto& el : elements) {
        for (int i = 0; i < k; ++i) {
            if (i < el.coeffs.size()) ss << bint_to_str(el.coeffs[i].get_value(), base) << " ";
            else ss << "0 ";
        }
    }
    return ss.str();
}

std::string Serializer::serialize_CurveFp(const EllipticCurve& curve, const std::vector<PointFp>& points, Base base) {
    std::stringstream ss;
    ss << (int)base << " " << (int)T_E_FP << " " 
       << bint_to_str(curve.a.get_modulus(), base) << " " 
       << bint_to_str(curve.a.get_value(), base) << " " 
       << bint_to_str(curve.b.get_value(), base) << " " 
       << points.size() << " ";

    for (const auto& P : points) {
        if (P.is_infinity) ss << "# # ";
        else ss << bint_to_str(P.x.get_value(), base) << " " << bint_to_str(P.y.get_value(), base) << " ";
    }
    return ss.str();
}

std::string Serializer::serialize_Curve(const EllipticCurveFpk& curve, const std::vector<PointFpk>& points, Base base) {
    std::stringstream ss;
    const Fpk& proto_a = curve.a;
    int k = proto_a.irreducible_poly->size() - 1;
    ss << (int)base << " " << (int)T_E_FPK << " " << bint_to_str(proto_a.get_p(), base) << " " << k << " ";
    for (const auto& coeff : *proto_a.irreducible_poly) ss << bint_to_str(coeff.get_value(), base) << " ";

    auto ser_fpk = [&](const Fpk& el) {
        for (int i = 0; i < k; ++i) {
            if (i < el.coeffs.size()) ss << bint_to_str(el.coeffs[i].get_value(), base) << " ";
            else ss << "0 ";
        }
    };
    ser_fpk(curve.a); ser_fpk(curve.b);
    ss << points.size() << " ";
    for (const auto& P : points) {
        if (P.is_infinity) ss << "# # ";
        else { ser_fpk(P.x); ser_fpk(P.y); }
    }
    return ss.str();
}

std::string Serializer::serialize_CurveBinary(const EllipticCurveBinary& curve, const std::vector<PointF2k>& points, Base base) {
    std::stringstream ss;
    ss << (int)base << " " << (int)T_E_F2K << " " << bint_to_str(curve.a.get_modulus(), base) << " " << bint_to_str(curve.a.get_value(), base) << " " << bint_to_str(curve.b.get_value(), base) << " " << points.size() << " ";
    for (const auto& P : points) {
        if (P.is_infinity) ss << "# # ";
        else ss << bint_to_str(P.x.get_value(), base) << " " << bint_to_str(P.y.get_value(), base) << " ";
    }
    return ss.str();
}

std::vector<Fp> Serializer::deserialize_Fp(const std::string& raw) {
    auto t = split(raw);
    Base b = (Base)std::stoi(t[0]);
    bInt p = str_to_bint(t[2], b);
    int count = std::stoi(t[3]);
    std::vector<Fp> res;
    for(int i=0; i<count; ++i) res.emplace_back(str_to_bint(t[4+i], b), p);
    return res;
}

std::vector<F2k> Serializer::deserialize_F2k(const std::string& raw) {
    auto t = split(raw);
    Base b = (Base)std::stoi(t[0]);
    bInt poly = str_to_bint(t[2], b);
    int count = std::stoi(t[3]);
    std::vector<F2k> res;
    for(int i=0; i<count; ++i) res.emplace_back(str_to_bint(t[4+i], b), poly);
    return res;
}

std::vector<Fpk> Serializer::deserialize_Fpk(const std::string& raw) {
    auto t = split(raw);
    Base b = (Base)std::stoi(t[0]);
    bInt p = str_to_bint(t[2], b);
    int k = std::stoi(t[3]);
    auto poly_ptr = std::make_shared<std::vector<Fp>>();
    for(int i=0; i<=k; ++i) poly_ptr->emplace_back(str_to_bint(t[4+i], b), p);
    int count = std::stoi(t[5+k]);
    std::vector<Fpk> res;
    int cur = 6+k;
    for(int i=0; i<count; ++i) {
        std::vector<Fp> c;
        for(int j=0; j<k; ++j) c.emplace_back(str_to_bint(t[cur++], b), p);
        res.emplace_back(c, poly_ptr);
    }
    return res;
}

std::pair<EllipticCurve, std::vector<PointFp>> Serializer::deserialize_CurveFp(const std::string& raw) {
    auto t = split(raw);
    Base b = (Base)std::stoi(t[0]);

    bInt p = str_to_bint(t[2], b);
    Fp a(str_to_bint(t[3], b), p);
    Fp b_coeff(str_to_bint(t[4], b), p);
    
    EllipticCurve curve(a, b_coeff);
    
    int count = std::stoi(t[5]);
    std::vector<PointFp> pts;
    
    for(int i=0; i < count; ++i) {
        int idx = 6 + i * 2;
        if (t[idx] == "#") {
            // FIX: curve.infinity() nie istnieje. Używamy metody statycznej PointFp
            pts.push_back(PointFp::make_infinity(&curve));
        } else {
            Fp x(str_to_bint(t[idx], b), p);
            Fp y(str_to_bint(t[idx+1], b), p);
            pts.emplace_back(x, y, &curve);
        }
    }
    return {curve, pts};
}

std::pair<EllipticCurveBinary, std::vector<PointF2k>> Serializer::deserialize_CurveBinary(const std::string& raw) {
    auto t = split(raw);
    Base b = (Base)std::stoi(t[0]);
    bInt poly = str_to_bint(t[2], b);
    EllipticCurveBinary curve(F2k(str_to_bint(t[3], b), poly), F2k(str_to_bint(t[4], b), poly));
    int count = std::stoi(t[5]);
    std::vector<PointF2k> pts;
    for(int i=0; i < count; ++i) {
        if (t[6+i*2] == "#") {
            // FIX: Używamy metody statycznej PointF2k
            pts.push_back(PointF2k::make_infinity(&curve));
        }
        else pts.emplace_back(F2k(str_to_bint(t[6+i*2], b), poly), F2k(str_to_bint(t[7+i*2], b), poly), &curve);
    }
    return {curve, pts};
}

std::pair<EllipticCurveFpk, std::vector<PointFpk>> Serializer::deserialize_Curve(const std::string& raw) {
    auto t = split(raw);
    Base b = (Base)std::stoi(t[0]);
    bInt p = str_to_bint(t[2], b);
    int k = std::stoi(t[3]);
    auto poly_ptr = std::make_shared<std::vector<Fp>>();
    for(int i=0; i<=k; ++i) poly_ptr->emplace_back(str_to_bint(t[4+i], b), p);
    int cur = 5+k;
    auto get_fpk = [&]() {
        std::vector<Fp> c;
        for(int j=0; j<k; ++j) c.emplace_back(str_to_bint(t[cur++], b), p);
        return Fpk(c, poly_ptr);
    };
    Fpk ca = get_fpk(); Fpk cb = get_fpk();
    EllipticCurveFpk curve(ca, cb);
    int count = std::stoi(t[cur++]);
    std::vector<PointFpk> pts;
    for(int i=0; i<count; ++i) {
        if(t[cur] == "#") { 
            // FIX: Tworzenie infinity przez metodę statyczną PointFpk
            pts.push_back(PointFpk::make_infinity(&curve)); 
            cur+=2; 
        }
        else { Fpk px = get_fpk(); Fpk py = get_fpk(); pts.emplace_back(px, py, &curve); }
    }
    return {curve, pts};
}

AnyStructure Serializer::deserialize(const std::string& raw) {
    if (raw.empty()) return std::monostate{};
    auto t = split(raw);
    if (t.size() < 2) return std::monostate{};
    int type = std::stoi(t[1]);
    switch (type) {
        case T_FP: return deserialize_Fp(raw);
        case T_F2K: return deserialize_F2k(raw);
        case T_FPK: return deserialize_Fpk(raw);
        case T_E_F2K: return deserialize_CurveBinary(raw);
        case T_E_FPK: return deserialize_Curve(raw);
        case T_E_FP: return deserialize_CurveFp(raw);
        default: return std::monostate{};
    }
}

OperationResult Serializer::executeONP(const AnyStructure& structure, const std::vector<std::string>& ops, Base base) {
    if (auto* vec = std::get_if<std::vector<Fp>>(&structure)) {
        std::stack<Fp> s;
        for (const auto& t : ops) {
            if (isdigit(t[0])) s.push((*vec)[std::stoi(t)]);
            else {
                Fp b = s.top(); s.pop();
                if (t == "~") { s.push(-b); continue; }
                if (t == "!") { s.push(b.inv()); continue; }
                if (s.empty()) return std::monostate{};
                Fp a = s.top(); s.pop();
                if (t == "+") s.push(a + b);
                else if (t == "-") s.push(a - b);
                else if (t == "*") s.push(a * b);
                else if (t == "^") s.push(a.pow(b.get_value()));
                else if (t == "/") s.push(a / b);
            }
        }
        return s.top();
    }
    if (auto* vec = std::get_if<std::vector<Fpk>>(&structure)) {
        std::stack<Fpk> s;
        for (const auto& t : ops) {
            if (isdigit(t[0])) s.push((*vec)[std::stoi(t)]);
            else {
                Fpk b = s.top(); s.pop();
                if (t == "!") { s.push(b.inv()); continue; }
                if (t == "~") { s.push(-b); continue; }
                if (s.empty()) return std::monostate{};
                Fpk a = s.top(); s.pop();
                if (t == "+") s.push(a + b);
                else if (t == "-") s.push(a - b);
                else if (t == "*") s.push(a * b);
                else if (t == "^") s.push(a.pow(b.coeffs[0].get_value()));
                else if (t == "/") s.push(a / b);
            }
        }
        return s.empty() ? OperationResult{} : s.top();
    }
    if (auto* vec = std::get_if<std::vector<F2k>>(&structure)) {
        std::stack<F2k> s;
        for (const auto& t : ops) {
            if (isdigit(t[0])) s.push((*vec)[std::stoi(t)]);
            else {
                F2k b = s.top(); s.pop();
                if (t == "~") continue;
                if (t == "!") { s.push(b.inv()); continue; }
                if (s.empty()) return std::monostate{};
                F2k a = s.top(); s.pop();
                if (t == "+") s.push(a + b);
                else if (t == "-") s.push(a - b);
                else if (t == "*") s.push(a * b);
                else if (t == "/") s.push(a / b);
            }
        }
        return s.top();
    }
    if (auto* pair = std::get_if<std::pair<EllipticCurveBinary, std::vector<PointF2k>>>(&structure)) {
        std::stack<PointF2k> s;
        for (const auto& t : ops) {
            if (isdigit(t[0])) s.push(pair->second[std::stoi(t)]);
            else if (t == "+")
            {
                PointF2k b = s.top(); s.pop();
                PointF2k a = s.top(); s.pop();
                s.push(a + b); // FIX: Używamy operatora+ punktu
            }
        }
        return s.top();
    }
    if (auto* pair = std::get_if<std::pair<EllipticCurveFpk, std::vector<PointFpk>>>(&structure)) {
        std::stack<PointFpk> s;
        for (const auto& t : ops) {
            if (isdigit(t[0])) s.push(pair->second[std::stoi(t)]);
            else if (t == "+") 
            {
                PointFpk b = s.top(); s.pop();
                PointFpk a = s.top(); s.pop();
                s.push(a + b); // FIX: Używamy operatora+ punktu
            }
        }
        return s.top();
    }
    if (auto* pair = std::get_if<std::pair<EllipticCurve, std::vector<PointFp>>>(&structure)) {
        std::stack<PointFp> s;
        for (const auto& t : ops) {
            if (isdigit(t[0])) s.push(pair->second[std::stoi(t)]);
            else if (t == "+") 
            {
                if (s.size() < 2) return std::monostate{};
                PointFp b = s.top(); s.pop();
                PointFp a = s.top(); s.pop();
                s.push(a + b); // FIX: Używamy operatora+ punktu
            }
        }
        return s.top();
    }
    return std::monostate{};
}

std::pair<AnyStructure, OperationResult> Serializer::deserializeWithAction(const std::string& raw) {
    auto tokens = split(raw);
    if (tokens.size() < 4) return {std::monostate{}, std::monostate{}};
    Base base = (Base)std::stoi(tokens[0]);
    int type = std::stoi(tokens[1]);
    AnyStructure data = deserialize(raw);
    size_t start = 0;
    switch (type) {
        case T_FP: 
        case T_F2K: start = 4 + std::stoi(tokens[3]); break;
        case T_FPK: {
            int k = std::stoi(tokens[3]);
            start = 4 + (k+1) + 1 + (std::stoi(tokens[4+k+1]) * k);
            break;
        }
        case T_E_F2K: start = 6 + (std::stoi(tokens[5]) * 2); break;
        case T_E_FP: start = 6 + (std::stoi(tokens[5]) * 2); break;
        case T_E_FPK: {
            int k = std::stoi(tokens[3]);
            int cp = 4 + (k+1) + k + k;
            start = cp + 1 + (std::stoi(tokens[cp]) * 2 * k);
            break;
        }
    }
    std::vector<std::string> ops;
    for (size_t i = start + 1; i < tokens.size(); ++i) 
    {
        ops.push_back(tokens[i]);
    }
    return {data, executeONP(data, ops, base)};
}