CFLAGS := -D _DEBUG -ggdb3 -O0 -Wall -Wextra -Waggressive-loop-optimizations -Wmissing-declarations -Wcast-align -Wcast-qual -Wchar-subscripts  -Wconversion -Wempty-body -Wfloat-equal -Wformat-nonliteral -Wformat-security -Wformat-signedness -Wformat=2 -Winline -Wlogical-op -Wopenmp-simd -Wpacked -Wpointer-arith -Winit-self -Wredundant-decls -Wshadow -Wsign-conversion -Wstrict-overflow=2 -Wsuggest-attribute=noreturn -Wsuggest-final-methods -Wsuggest-final-types -Wswitch-default -Wswitch-enum -Wsync-nand -Wundef -Wunreachable-code -Wunused -Wuseless-cast -Wvariadic-macros -Wno-missing-field-initializers -Wno-narrowing -Wno-varargs -Wstack-protector -fcheck-new -fstack-protector -fstrict-overflow -fno-omit-frame-pointer -Wlarger-than=8192 -Wstack-usage=8192 -pie -fPIE -Werror=vla -fsanitize=address,alignment,bool,bounds,enum,float-cast-overflow,float-divide-by-zero,integer-divide-by-zero,leak,nonnull-attribute,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,undefined,unreachable,vla-bound,vptr -Iinclude -D _GNU_SOURCE

CXXFLAGS := $(CFLAGS) -Weffc++ -Wc++14-compat -Wconditionally-supported -Wctor-dtor-privacy -Wnon-virtual-dtor -Woverloaded-virtual -Wsign-promo -Wstrict-null-sentinel -Wsuggest-override -Wno-literal-suffix -Wno-old-style-cast -std=c++17 -fsized-deallocation

CXX := g++
CC := gcc
FLAGS := $(CXXFLAGS)

LDFLAGS := -lm

# Uncomment next two lines for C compiler
# OBJCFLAGS := -xc -std=c11
# FLAGS := $(CFLAGS)
# CXX := $(CC)

ifdef USE_GTEST
override CFLAGS += -DUSE_GTEST
endif

export CXX CFLAGS

# -flto-odr-type-merging

BUILD_DIR := build

LIBSRC := src/pvector.cpp src/gdb_assertions.cpp
LIBOBJ := $(LIBSRC:%.cpp=$(BUILD_DIR)/%.o)
STATIC_LIB := $(BUILD_DIR)/stack_lib.a

TESTLIBSRC := test/test_machine.cpp
TESTLIBOBJ := $(TESTLIBSRC:%.cpp=$(BUILD_DIR)/%.o)

TESTSRC := test/test_pvector.cpp test/test_stack.cpp
TESTOBJ := $(TESTSRC:%.cpp=$(BUILD_DIR)/%.o)
TEST_LIB_APP := $(BUILD_DIR)/test_stack

CPPSRC := #src/stack.cpp
CPPOBJ := $(CPPSRC:%.cpp=$(BUILD_DIR)/%.o)
APP := #$(BUILD_DIR)/stack_st

INCPDSRC := $(CPPSRC) $(TESTSRC) $(LIBSRC) $(TESTLIBSRC)
incpd := $(INCPDSRC:%.cpp=$(BUILD_DIR)/%.d)

OBJDIRS := $(sort $(dir $(LIBOBJ) $(TESTOBJ) $(CPPOBJ) $(TESTLIBOBJ)))

define INCFIRE
	@echo IN CASE OF FIRE
	@echo GIT COMMIT
	@echo GIT PUSH
	@echo MEOW
	@echo LEAVE BUILDING
	@echo THE TARGET IS BUILT SUCCSESSFULLY
	@echo
endef

.PHONY: build clean run test document build_test objdirs

build: $(APP) $(STATIC_LIB)
	$(INCFIRE)

run: build
	./$(APP)

$(OBJDIRS):
	mkdir -p $(OBJDIRS)

$(CPPOBJ) $(TESTOBJ) $(LIBOBJ) $(TESTLIBOBJ): $(BUILD_DIR)/%.o: %.cpp
	mkdir -p $(OBJDIRS)
	# $< takes only the FIRST dependency
	$(CXX) $(FLAGS) $(OBJCFLAGS) -MP -MMD -c $< -o $@

$(STATIC_LIB): $(LIBOBJ)
	ar rvs $@ $^

ifdef USE_GTEST
$(TEST_LIB_APP): $(STATIC_LIB) $(TESTOBJ)
	$(CXX) $(FLAGS) $(LDFLAGS) $(TESTOBJ) $(STATIC_LIB) -lgtest_main -lgtest -o $(TEST_LIB_APP)
else
$(TEST_LIB_APP): $(STATIC_LIB) $(TESTOBJ) $(TESTLIBOBJ)
	$(CXX) $(FLAGS) $(LDFLAGS) $(TESTOBJ) $(TESTLIBOBJ) $(STATIC_LIB) -o $(TEST_LIB_APP)
endif


build_test: $(TEST_LIB_APP)
	$(INCFIRE)

test: build_test
	./$(TEST_LIB_APP)

$(APP): $(CPPOBJ) $(STATIC_LIB)
	$(CXX) $(FLAGS) $(LDFLAGS) $(CPPOBJ) $(STATIC_LIB) -o $(APP)

document: objdirs
	doxygen doxygen.conf

clean:
	rm -rf build

-include $(incpd)
