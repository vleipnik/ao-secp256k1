#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>

#include <emscripten.h>

#ifdef __cplusplus
#include "lua.hpp"
#else
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#endif

#include "gmp.h"

#ifdef __cplusplus
extern "C"
{
#endif

bool compute_mod_exp(const char *base_input, const char *exp_input, const char *mod_input, const char *expected_input) {
    mpz_t base, exp, mod, large_exp, result, expected;
    bool match = false;

    // Initialize big integers
    mpz_init(base);
    mpz_init(exp);
    mpz_init(mod);
    mpz_init(large_exp);
    mpz_init(result);
    mpz_init(expected);

    // Set inputs to GMP integers (assume hex without needing 0x prefix)
    if (mpz_set_str(base, base_input, 16) != 0) {
        printf("Invalid base input!\n");
        goto cleanup;
    }

    if (mpz_set_str(exp, exp_input, 10) != 0) {
        printf("Invalid exponent input!\n");
        goto cleanup;
    }

    if (mpz_set_str(mod, mod_input, 16) != 0 || mpz_cmp_ui(mod, 0) <= 0) {
        printf("Invalid modulus input or modulus must be positive!\n");
        goto cleanup;
    }

    if (expected_input && mpz_set_str(expected, expected_input, 16) != 0) {
        printf("Invalid expected result input!\n");
        goto cleanup;
    }

    // Compute 2^exp
    mpz_ui_pow_ui(large_exp, 2, mpz_get_ui(exp));

    // Perform modular exponentiation: result = base^(2^exp) % mod
    mpz_powm(result, base, large_exp, mod);

    // Compare the result with the expected value
    if (expected_input && mpz_cmp(result, expected) == 0) {
        match = true;
    }

cleanup:
    // Clear memory
    mpz_clears(base, exp, mod, large_exp, result, expected, NULL);
    return match;
}

// Lua wrapper for compute_mod_exp
int lua_compute_mod_exp(lua_State *L) {
    // Get parameters from Lua (stack order: base, exponent, modulus, expected)
    const char *base = luaL_checkstring(L, 1);
    const char *exp = luaL_checkstring(L, 2);
    const char *mod = luaL_checkstring(L, 3);
    const char *expected = luaL_checkstring(L, 4);

    // Call the C function
    bool result = compute_mod_exp(base, exp, mod, expected);

    // Push the result (boolean) back to Lua
    lua_pushboolean(L, result);
    return 1;  // Number of return values
}

bool check_modulus_result(const char *input, const char *modulus, const char *expected) {
    mpz_t bint_input, bint_modulus, bint_expected, result;
    bool match = false;

    // Initialize GMP integers
    mpz_init(bint_input);
    mpz_init(bint_modulus);
    mpz_init(bint_expected);
    mpz_init(result);

    // Set input and modulus values (assume hex format)
    if (mpz_set_str(bint_input, input, 16) != 0) {
        printf("Invalid input value!\n");
        goto cleanup;
    }

    if (mpz_set_str(bint_modulus, modulus, 16) != 0 || mpz_cmp_ui(bint_modulus, 0) <= 0) {
        printf("Invalid modulus value!\n");
        goto cleanup;
    }

    // Set expected value (assume decimal format)
    if (mpz_set_str(bint_expected, expected, 10) != 0) {
        printf("Invalid expected output value!\n");
        goto cleanup;
    }

    // Perform modulus operation: result = input % modulus
    mpz_mod(result, bint_input, bint_modulus);

    // Print debug information
    printf("Input: ");
    gmp_printf("%Zd\n", bint_input);

    printf("Modulus: ");
    gmp_printf("%Zd\n", bint_modulus);

    printf("Expected Output (decimal): ");
    gmp_printf("%Zd\n", bint_expected);

    printf("Result (decimal): ");
    gmp_printf("%Zd\n", result);

    // Compare result with expected output
    if (mpz_cmp(result, bint_expected) == 0) {
        match = true;
    }

cleanup:
    // Clear memory
    mpz_clears(bint_input, bint_modulus, bint_expected, result, NULL);
    return match;
}

// Lua wrapper for check_modulus_result
int lua_check_modulus_result(lua_State *L) {
    // Get parameters from Lua (stack order: input, modulus, expected)
    const char *input = luaL_checkstring(L, 1);
    const char *modulus = luaL_checkstring(L, 2);
    const char *expected = luaL_checkstring(L, 3);

    // Call the C function
    bool result = check_modulus_result(input, modulus, expected);

    // Push the result (boolean) back to Lua
    lua_pushboolean(L, result);
    return 1;  // Number of return values
}

  int boot_lua(lua_State *L);
  lua_State *wasm_lua_state = NULL;

  // Pre-compiled lua loader program
  static const unsigned char program[] = {__LUA_BASE__};
  // Pre-compiled entry script which user wrote
  static const unsigned char lua_main_program[] = {__LUA_MAIN__};

  // This line will be injected by emcc-lua as export functions to WASM declaration
  __FUNCTION_DECLARATIONS__

    // This function is for debug to see an C <-> Lua stack values
  // void dumpStack(lua_State *L) {
  //   int i;
  //   int stackSize = lua_gettop(L);
  //   for (i = stackSize; i >= 1; i--) {
  //     int stackType = lua_type(L, i);
  //     printf("Stack[%2d-%10s]:", i, lua_typename(L, stackType));
  //
  //     switch (stackType) {
  //       case LUA_TNUMBER:
  //         printf("%f", lua_tonumber(L, i));
  //         break;
  //       case LUA_TBOOLEAN:
  //         if (lua_toboolean(L, i)) {
  //           printf("true");
  //         } else {
  //           printf("false");
  //         }
  //         break;
  //       case LUA_TSTRING:
  //         printf("%s", lua_tostring(L, i));
  //         break;
  //       case LUA_TNIL:
  //         printf("nil");
  //         break;
  //       default:
  //         printf("%s", lua_typename(L, stackType));
  //         break;
  //     }
  //     printf("\n");
  //   }
  //   printf("\n");
  // }

  /* Copied from lua.c */

  static lua_State *globalL = NULL;

  static void lstop(lua_State *L, lua_Debug *ar)
  {
    (void)ar;                   /* unused arg. */
    lua_sethook(L, NULL, 0, 0); /* reset hook */
    luaL_error(L, "interrupted!");
  }

  static void laction(int i)
  {
    signal(i, SIG_DFL); /* if another SIGINT happens, terminate process */
    lua_sethook(globalL, lstop, LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT, 1);
  }

  static int msghandler(lua_State *L)
  {
    const char *msg = lua_tostring(L, 1);
    if (msg == NULL)
    {                                          /* is error object not a string? */
      if (luaL_callmeta(L, 1, "__tostring") && /* does it have a metamethod */
          lua_type(L, -1) == LUA_TSTRING)      /* that produces a string? */
        return 1;                              /* that is the message */
      else
        msg = lua_pushfstring(L, "(error object is a %s value)",
                              luaL_typename(L, 1));
    }
    /* Call debug.traceback() instead of luaL_traceback() for Lua 5.1 compatibility. */
    lua_getglobal(L, "debug");
    lua_getfield(L, -1, "traceback");
    /* debug */
    lua_remove(L, -2);
    lua_pushstring(L, msg);
    /* original msg */
    lua_remove(L, -3);
    lua_pushinteger(L, 2); /* skip this function and traceback */
    lua_call(L, 2, 1);     /* call debug.traceback */
    return 1;              /* return the traceback */
  }

  static int docall(lua_State *L, int narg, int nres)
  {
    int status;
    int base = lua_gettop(L) - narg;  /* function index */
    lua_pushcfunction(L, msghandler); /* push message handler */
    lua_insert(L, base);              /* put it under function and args */
    globalL = L;                      /* to be available to 'laction' */
    signal(SIGINT, laction);          /* set C-signal handler */
    status = lua_pcall(L, narg, nres, base);
    signal(SIGINT, SIG_DFL); /* reset C-signal handler */
    lua_remove(L, base);     /* remove message handler from the stack */
    return status;
  }

  // Boot function
  int main(void)
  {
    if (wasm_lua_state != NULL)
    {
      return 0;
    }
    wasm_lua_state = luaL_newstate();
    if (boot_lua(wasm_lua_state))
    {
      printf("failed to boot lua runtime\\n");
      lua_close(wasm_lua_state);
      return 1;
    }
    // printf("Boot Lua Webassembly!\n");
    return 0;
  }

  // boot lua runtime from compiled lua source
  int boot_lua(lua_State *L)
  {
    luaL_openlibs(L);

    // luaL_getsubtable(L, LUA_REGISTRYINDEX, LUA_PRELOAD_TABLE);
    // lua_pushcfunction(L, luaopen_mylib);
    // lua_setfield(L, -2, "mylib");
    // lua_pop(L, 1);  // remove PRELOAD table

    if (luaL_loadbuffer(L, (const char *)program, sizeof(program), "main"))
    {
      fprintf(stderr, "error on luaL_loadbuffer()\n");
      return 1;
    }
    lua_newtable(L);
    lua_pushlstring(L, (const char *)lua_main_program, sizeof(lua_main_program));
    lua_setfield(L, -2, "__lua_webassembly__");

    lua_register(wasm_lua_state, "compute_mod_exp", lua_compute_mod_exp);
    lua_register(wasm_lua_state, "check_modulus_result", lua_check_modulus_result);

    // This place will be injected by emcc-lua
    __INJECT_LUA_FILES__

    if (docall(L, 1, LUA_MULTRET))
    {
      const char *errmsg = lua_tostring(L, 1);
      if (errmsg)
      {
        fprintf(stderr, "%s\n", errmsg);
      }
      lua_close(L);
      return 1;
    }
    return 0;
  }

#ifdef __cplusplus
}
#endif