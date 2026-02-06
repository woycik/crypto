#include "gtest/gtest.h"
#include <vector>
#include <cstdint>
#include <stdexcept>
#include "../zad3.hpp" 


TEST(RotationTest, RotateLeftCheck)
{
    uint32_t x = 0x12345678;
    EXPECT_EQ(rol(x, 4), 0x23456781u);

    EXPECT_EQ(rol(x, 0), x);
    EXPECT_EQ(rol(x, 32), x);
    EXPECT_EQ(rol(x, 12), 0x45678123u);
}

TEST(RotationTest, RotateRightCheck)
{
    uint32_t x = 0x12345678;
    EXPECT_EQ(ror(x, 4), 0x81234567u);

    EXPECT_EQ(ror(x, 0), x);
    EXPECT_EQ(ror(x, 32), x);
    EXPECT_EQ(ror(x, 12), 0x67812345u);
}

TEST(CollisionTest, CheckIfMessagesAreTheSame) 
{   

    uint32_t M0_buffer[4] =  {0x52589324, 0x3093d7ca, 0x2a06dc54, 0x20c5be06};
    //uint32_t M0_buffer[4] =  {0xd2589324, 0xb293d7ca, 0xac06dc54, 0xa2c5be06};

    uint32_t M1_original[16];
    uint32_t M1p_original[16];

    memcpy(M1_original, M1, sizeof(M1));  
    memcpy(M1p_original, M1, sizeof(M1));

    std::cout << "M1 original: ";
    for (const auto& word : M1_original) std::cout << std::hex << word << " ";
    std::cout << std::endl;
    
    EXPECT_TRUE(check_if_messages_are_the_sama(M1_original, M1p_original, M0_buffer));

    std::cout << "After" << std::endl;
    for (const auto& word : M1_original) std::cout << std::hex << word << " ";
    std::cout << std::endl;

}

TEST (CollisionTest, FindCollision) {
    EXPECT_TRUE(find_collision_test());
}

TEST (CollisionTest, FindCollision2) {
    EXPECT_TRUE(find_collision2_test());
}

TEST (CollisionTest, FindCollision3) {
    EXPECT_TRUE(find_collision3_test());
}