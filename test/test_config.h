#ifndef TEST_CONFIG_H
#define TEST_CONFIG_H

#ifdef USE_GTEST

#include <gtest/gtest.h>

#else /* USE_GTEST */

#include "test_machine.h"

#endif /* USE_GTEST */



#ifdef TEST_DEBUG

#define printf_debug_log(...) printf(__VA_ARGS__)

#else /* TEST_DEBUG */

#define printf_debug_log(...) (void)0

#endif /* TEST_DEBUG */


#endif /* TEST_CONFIG_H */
