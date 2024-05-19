#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>

const char* TR_PRIMES[] = {"2", "3", "5", "7", "11", "13", "17", "19", "23", "29", "31", "37", "41", "43", "47"};
const int NUM_PRIMES = sizeof(TR_PRIMES) / sizeof(TR_PRIMES[0]);


// uint64_t dlp_bruteforce(uint64_t a, uint64_t p, uint64_t b);

// void mpz_power(mpz_t a, mpz_t b, mpz_t p, mpz_t result);
// uint64_t power(uint64_t a, uint64_t b, uint64_t p); //interface for ctypes

// void xgcd(mpz_t a, mpz_t b, mpz_t g, mpz_t x, mpz_t y);
// void mpz_inv(mpz_t a, mpz_t p, mpz_t result);
// uint64_t inv(uint64_t a, uint64_t p); //interface for ctypes

//bruteforce
uint64_t dlp_bruteforce(uint64_t a, uint64_t b, uint64_t p) {
  uint64_t result = 1;
  for (uint64_t i = 0; i < p; i++) {
    if (result == b) {
      return i;
    }
    result = (result * a) % p;
  }
  return -1;
}

//binary exp
void mpz_power(mpz_t a, mpz_t b, mpz_t p, mpz_t result) {
    mpz_set_ui(result, 1);
    mpz_t base, temp, dec;
    mpz_init_set(base, a);
    mpz_init(temp);
    mpz_init_set(dec, b);
    mpz_mod(base, base, p); // base = base % p


    while (mpz_cmp_ui(dec, 0) > 0) {
        if (mpz_odd_p(dec)) {
            mpz_mul(temp, result, base); // temp = result * base
            mpz_mod(result, temp, p); // result = temp % p
        }
        mpz_tdiv_q_ui(dec, dec, 2); // b = b / 2
        mpz_mul(temp, base, base); // temp = base * base
        mpz_mod(base, temp, p); // base = temp % p
    }

    mpz_clear(base);
    mpz_clear(temp);
    mpz_clear(dec);
}

uint64_t power(uint64_t a, uint64_t b, uint64_t p) {
    mpz_t mpz_a, mpz_b, mpz_p, result;
    mpz_init_set_ui(mpz_a, a);
    mpz_init_set_ui(mpz_b, b);
    mpz_init_set_ui(mpz_p, p);
    mpz_init_set_ui(result,1);

    mpz_power(mpz_a, mpz_b, mpz_p, result);

    uint64_t res = mpz_get_ui(result);
    mpz_clear(mpz_a);
    mpz_clear(mpz_b);
    mpz_clear(mpz_p);
    mpz_clear(result);
    return res;
}

void xgcd(mpz_t a, mpz_t b, mpz_t g, mpz_t x, mpz_t y) {
    if (mpz_cmp_ui(a, 0) == 0) {
        mpz_set_ui(x, 0);
        mpz_set_ui(y, 1);
        mpz_set(g, b);
    } else {
        mpz_t x0, y0, temp;
        mpz_init(x0);
        mpz_init(y0);
        mpz_init(temp);

        mpz_mod(temp, b, a);
        xgcd(temp, a, g, x0, y0);

        mpz_fdiv_q(temp, b, a);
        mpz_mul(temp, temp, x0);
        mpz_sub(x, y0, temp);
        mpz_set(y, x0);

        mpz_clear(x0);
        mpz_clear(y0);
        mpz_clear(temp);
    }
}



void mpz_inv(mpz_t a, mpz_t p, mpz_t result) {
    mpz_t x, y, g;
    mpz_init(x);
    mpz_init(y);
    mpz_init(g);

    xgcd(a, p, g, x, y);
    if (mpz_cmp_ui(g, 1) != 0) {
        // gmp_printf("a = %Zd, p = %Zd\n", a, p);
        printf("Inverse does not exist\n");
        mpz_set_ui(result, 0);
    } else {
        if (mpz_cmp_si(x, 0) < 0) {
            mpz_add(x, x, p);
        }
        mpz_mod(result, x, p);
    }

    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(g);
}

uint64_t inv(uint64_t a, uint64_t p) {
    mpz_t mpz_a, mpz_p, result;
    mpz_init_set_ui(mpz_a, a);
    mpz_init_set_ui(mpz_p, p);
    mpz_init(result);

    mpz_inv(mpz_a, mpz_p, result);

    uint64_t res = mpz_get_ui(result);
    mpz_clear(mpz_a);
    mpz_clear(mpz_p);
    mpz_clear(result);
    return res;
}


void rhoPolard(mpz_t n, mpz_t x0, mpz_t result) {
    mpz_t x, y, d, temp;
    mpz_inits(x, y, d, temp, NULL);
    mpz_set(x, x0);
    mpz_set(y, x0);
    mpz_set_ui(d, 1);

    while (mpz_cmp_ui(d, 1) == 0) {
        mpz_mul(temp, x, x);
        mpz_add_ui(temp, temp, 1);
        mpz_mod(x, temp, n);

        mpz_mul(temp, y, y);
        mpz_add_ui(temp, temp, 1);
        mpz_mod(temp, temp, n);
        mpz_mul(temp, temp, temp);
        mpz_add_ui(temp, temp, 1);
        mpz_mod(y, temp, n);

        mpz_sub(temp, x, y);
        mpz_abs(temp, temp);
        mpz_gcd(d, temp, n);
    }

    mpz_set(result, d);

    mpz_clears(x, y, d, temp, NULL);
}

void rpFactor(mpz_t n, mpz_t result) {
    mpz_t x0;
    mpz_init_set_ui(x0, 2);
    rhoPolard(n, x0, result);
    mpz_clear(x0);
}


uint64_t factor(uint64_t n) {
    mpz_t mpz_n, result;
    mpz_init_set_ui(mpz_n, n);
    mpz_init(result);

    rpFactor(mpz_n, result);

    uint64_t res = mpz_get_ui(result);
    mpz_clear(mpz_n);
    mpz_clear(result);
    return res;
}

int mrIter(mpz_t base, mpz_t num) {
    int power, iterations;
    mpz_t baseRaised, numMinusOne, temp;
    mpz_init(numMinusOne);
    mpz_sub_ui(numMinusOne, num, 1);

    power = 0;
    mpz_init_set(temp, numMinusOne);
    while (mpz_even_p(temp)) {
        mpz_fdiv_q_2exp(temp, temp, 1);
        power++;
    }

    mpz_init(baseRaised);
    mpz_powm(baseRaised, base, temp, num);

    if (mpz_cmp_ui(baseRaised, 1) == 0) {
        mpz_clears(baseRaised, temp, numMinusOne, NULL);
        return 1;
    }

    for(iterations = 0; iterations < power - 1; iterations++) {
        if (mpz_cmp(baseRaised, numMinusOne) == 0) {
            mpz_clears(baseRaised, temp, numMinusOne, NULL);
            return 1;
        }
        mpz_powm_ui(baseRaised, baseRaised, 2, num);
    }

    if (mpz_cmp(baseRaised, numMinusOne) == 0) {
        mpz_clears(baseRaised, temp, numMinusOne, NULL);
        return 1;
    }

    mpz_clears(baseRaised, temp, numMinusOne, NULL);
    return 0;
}

void trivialFactor(mpz_t result, const mpz_t n) {
    mpz_t temp;
    mpz_init(temp);

    for (int i = 0; i < NUM_PRIMES; i++) {
        mpz_set_str(temp, TR_PRIMES[i], 10);
        if (mpz_divisible_p(n, temp)) {
            mpz_set(result, temp);
            mpz_clear(temp);
            return;
        }
    }

    mpz_set(result, n);
    mpz_clear(temp);
}

int isMillerRabin(mpz_t num, gmp_randstate_t randState) {
    mpz_t randomNum;
    int repeat;
    mpz_init(randomNum);
    for(repeat = 0; repeat < 20; repeat++) {
        do {
            mpz_urandomm(randomNum, randState, num);
        } while (mpz_sgn(randomNum) == 0);

        if (mrIter(randomNum, num) == 0) {
            mpz_clear(randomNum);
            return 0;
        }
    }
    mpz_clear(randomNum);
    return 1;
}

uint64_t isPrime(uint64_t n) {
    mpz_t mpz_n;
    mpz_init_set_ui(mpz_n, n);
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);
    int res = isMillerRabin(mpz_n, rand_state);
    gmp_randclear(rand_state);
    mpz_clear(mpz_n);
    return res;
}

typedef struct {
    mpz_t factor;
    mpz_t power;
} FactorPowerPair;

FactorPowerPair* factorize(mpz_t mpz_n, int* numFactors) {
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);

    FactorPowerPair* factors = malloc(sizeof(FactorPowerPair) * mpz_sizeinbase(mpz_n, 2));
    *numFactors = 0;

    if (isMillerRabin(mpz_n, rand_state)) {
        mpz_init_set(factors[*numFactors].factor, mpz_n);
        mpz_init_set_ui(factors[*numFactors].power, 1);
        (*numFactors)++;
    } else {
        while (1) {
            mpz_t factor;
            mpz_init(factor);
            rpFactor(mpz_n, factor);

            mpz_t count;
            mpz_init_set_ui(count, 1);

            while (!isMillerRabin(factor, rand_state)){
                trivialFactor(factor, factor);
            }

            // Check if factor is already in the factors array
            int found = 0;
            for (int i = 0; i < *numFactors; i++) {
                if (mpz_cmp(factors[i].factor, factor) == 0) {
                    mpz_add_ui(factors[i].power, factors[i].power, 1);
                    found = 1;
                    break;
                }
            }

            // If factor is not in the factors array, add it
            if (!found) {
                mpz_init_set(factors[*numFactors].factor, factor);
                mpz_init_set(factors[*numFactors].power, count);
                (*numFactors)++;
            }

            mpz_divexact(mpz_n, mpz_n, factor);
            if (isMillerRabin(mpz_n, rand_state)) {
                mpz_init_set(factors[*numFactors].factor, mpz_n);
                mpz_init_set_ui(factors[*numFactors].power, 1);
                (*numFactors)++;
                break;
            }

            mpz_clear(count);
        }
    }

    gmp_randclear(rand_state);

    return factors;
}


void factorizeAndPrint(uint64_t n) {
    mpz_t mpz_n;
    mpz_init_set_ui(mpz_n, n);

    int numFactors;
    FactorPowerPair* factors = factorize(mpz_n, &numFactors);

    gmp_printf("%lu = ", n);
    for (int i = 0; i < numFactors; i++) {
        gmp_printf("%Zd^%Zd", factors[i].factor, factors[i].power);
        if (i < numFactors - 1) {
            gmp_printf(" * ");
        }
    }
    gmp_printf("\n");

    for (int i = 0; i < numFactors; i++) {
        mpz_clears(factors[i].factor, factors[i].power, NULL);
    }
    free(factors);
    mpz_clear(mpz_n);
}




uint64_t dlp_sph(uint64_t a, uint64_t b, uint64_t p) {
    mpz_t mpz_a, mpz_b, mpz_p, mpz_n, mpz_temp, mpz_temp_x, mpz_result;
    mpz_init_set_ui(mpz_a, a);
    mpz_init_set_ui(mpz_b, b);
    mpz_init_set_ui(mpz_p, p);

    mpz_init_set_ui(mpz_n, p - 1);

    mpz_init(mpz_temp);
    mpz_init_set_ui(mpz_result, 0);

    mpz_t mpz_nf;
    mpz_init_set(mpz_nf, mpz_n);
    

    int numFactors;
    FactorPowerPair* factors = factorize(mpz_nf, &numFactors);

    // gmp_printf("%Zd = ", mpz_n);
    // for (int i = 0; i < numFactors; i++) {
    //     gmp_printf("%Zd^%Zd", factors[i].factor, factors[i].power);
    //     if (i < numFactors - 1) {
    //         gmp_printf(" * ");
    //     }
    // }
    // gmp_printf("\n");

    mpz_clear(mpz_nf);

    mpz_t** table = malloc(sizeof(mpz_t*) * numFactors);
    if (!table) {
        printf("Error allocating memory\n");
        return 1;
    }

    for (int i = 0; i < numFactors; i++) {
        table[i] = malloc(sizeof(mpz_t) * mpz_get_ui(factors[i].factor));
        if (!table[i]) {
            printf("Error allocating memory\n");
            return 1;
        }
        for (int j = 0; j < mpz_get_ui(factors[i].factor); j++) {
            mpz_init_set_ui(table[i][j], 1);
            mpz_mul_ui(mpz_temp, mpz_n, j);
            mpz_div(mpz_temp, mpz_temp, factors[i].factor);

            mpz_power(mpz_a, mpz_temp, mpz_p, table[i][j]);
            
        }
    }

    mpz_t base, mod, mpz_x, mpz_c, mpz_d, mpz_i, mpz_inv_temp;
    mpz_init(base);
    mpz_init(mod);
    mpz_init(mpz_x);
    mpz_init(mpz_c);
    mpz_init(mpz_d);
    mpz_init(mpz_i);
    mpz_init(mpz_inv_temp);

    mpz_init(mpz_temp_x);
    for (int i = 0; i < numFactors; i++) {
        mpz_set(base, factors[i].factor);

    
        mpz_power(base, factors[i].power, mpz_p, mod);
        mpz_set_ui(mpz_x, 0);

        for (int j = 0; j < mpz_get_ui(factors[i].power); j++) {
            // printf("j = %d\n", j);
            
            // printf("--------------------\n");   
            // gmp_printf("mpz_x = %Zd\n", mpz_x);
            // gmp_printf("mpz_a = %Zd\n", mpz_a);
            mpz_power(mpz_a, mpz_x, mpz_p, mpz_temp);
            // printf("--------------------\n");
            // gmp_printf("mpz_temp = %Zd\n", mpz_temp);
            // gmp_printf("mpz_p = %Zd\n", mpz_p);
            mpz_inv(mpz_temp, mpz_p, mpz_inv_temp);  //inv not ex

            // gmp_printf("mpz_inv_temp = %Zd\n", mpz_inv_temp);
            // gmp_printf("mpz_b = %Zd\n", mpz_b);
            mpz_mul(mpz_temp, mpz_inv_temp, mpz_b);
            
            mpz_set(mpz_c, mpz_temp);
            // mpz_mod(mpz_c, mpz_c, mpz_p);
            //c = b * pow(a, -x, p)

            mpz_set_ui(mpz_i, j + 1);
            // gmp_printf("base = %Zd\n", base);
            // gmp_printf("mpz_i = %Zd\n", mpz_i); 
            mpz_set_ui(mpz_temp, 1);
            mpz_power(base, mpz_i, mpz_p, mpz_temp);
            // gmp_printf("mpz_temp = %Zd\n", mpz_temp);
            // gmp_printf("mpz_n = %Zd\n", mpz_n);
            mpz_div(mpz_d, mpz_n, mpz_temp);
            //d = n // base ** (j + 1)


            // gmp_printf("mpz_c = %Zd\n", mpz_c);
            // gmp_printf("mpz_d = %Zd\n", mpz_d);
            // gmp_printf("mpz_p = %Zd\n", mpz_p);
            mpz_power(mpz_c, mpz_d, mpz_p, mpz_temp_x);

            // gmp_printf("mpz_temp_x = %Zd\n", mpz_temp_x);
            int ind = -1;

            for (int k = 0; k < mpz_get_ui(base); k++) {
                // gmp_printf("table[%d][%d] = %Zd\n", i, k, table[i][k]);
                if (mpz_cmp(table[i][k], mpz_temp_x) == 0) {
                    ind = k;
                    break;
                }
            }
            if (ind == -1) {
                printf("Error: Could not find index\n");
            }
            // printf("*******************\n");
        
            mpz_set_ui(mpz_i, j);
            mpz_power(base, mpz_i, mpz_p, mpz_temp);
            // gmp_printf("mpz_temp = %Zd\n", mpz_temp);
            // printf("ind = %d\n", ind);

            mpz_mul_ui(mpz_temp, mpz_temp, ind);
            // gmp_printf("mpz_x = %Zd\n", mpz_x);
            // gmp_printf("mpz_temp = %Zd\n", mpz_temp);
            mpz_add(mpz_x, mpz_x, mpz_temp);
            // gmp_printf("mpz_x = %Zd\n", mpz_x);
            mpz_clear(mpz_temp_x);
            mpz_init(mpz_temp_x);
        }
        // gmp_printf("mpz_c = %Zd\n", mpz_c);
        // gmp_printf("mpz_n = %Zd\n", mpz_n);
        // gmp_printf("mod = %Zd\n", mod);
        mpz_div(mpz_c, mpz_n, mod);
        //c = n // mod

        // gmp_printf("mpz_c = %Zd\n", mpz_c);
        // gmp_printf("mod = %Zd\n", mod);
        mpz_inv(mpz_c, mod, mpz_d);
        //d = c ** -1 % mod

        mpz_mul(mpz_temp_x, mpz_x, mpz_c);
        mpz_mod(mpz_temp_x, mpz_temp_x, mpz_n);
        //x` = x * c % n

        mpz_mul(mpz_temp_x, mpz_temp_x, mpz_d);
        mpz_mod(mpz_temp_x, mpz_temp_x, mpz_n);
        //x` = x` * d % n
        // x` = x * c * d % n == x * (n // mod) * pow((n // mod), -1, mod) % n

        mpz_add(mpz_result, mpz_result, mpz_temp_x);

    }

    mpz_mod(mpz_result, mpz_result, mpz_n);

    uint64_t res = mpz_get_ui(mpz_result);
    // printf("Result: %lu\n", res);

    mpz_clear(base);
    mpz_clear(mod);
    mpz_clear(mpz_x);
    mpz_clear(mpz_c);
    mpz_clear(mpz_d);
    mpz_clear(mpz_i);
    mpz_clear(mpz_inv_temp);
    //start freeing memory
    for (int i = 0; i < numFactors; i++) {
        for (int j = 0; j < mpz_get_ui(factors[i].factor); j++) {
            mpz_clear(table[i][j]);
        }
        free(table[i]);
        table[i] = NULL;
    }
    free(table);
    table = NULL;

    for (int i = 0; i < numFactors; i++) {
        mpz_clear(factors[i].factor);
        mpz_clear(factors[i].power);
    }
    free(factors);

    mpz_clears(mpz_a, mpz_b, mpz_p, mpz_n, mpz_temp, mpz_temp_x, mpz_result, NULL);
    return res;
}