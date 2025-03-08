# **sca-protected-rsa**

This project implements countermeasures against **Side-Channel Attacks (SCA)** and **Fault Injection Attacks** in the RSA implementation of **BearSSL**.

---

## Acknowledgments

- This repository is inspired by the work in the [sca25519](https://github.com/sca-secure-library-sca25519/sca25519) project. Special thanks to the authors for their contributions.
- The RSA implementation is based on [BearSSL](https://www.bearssl.org/). Please refer to their website for more information.

---

## Installation

This project requires the following tools:
- **arm-none-eabi-gcc**: ARM cross-compiler toolchain.
- **python3** with **pyserial**: For communication with the device.
- **stlink**: For flashing the STM32F4 Discovery board.

### Setup Steps

1. **Initialize and Update Submodules**

  The project uses [libopencm3](https://github.com/libopencm3/libopencm3) as a submodule. Run:
   ```bash
   git submodule update --init --recursive
   ```
2. **Build the libopencm3 Library**
  Before building the project, compile the libopencm3 library:
    ```bash
     make lib
    ```
3. **Compile the Project**
  Once the library is built, compile the project by running:
   ```bash
   make
   ```
4. **Flash the Code**
  After a successful build, flash the compiled code to your connected STM32F4 Discovery board with:
    ```bash
    make flash
    ```

---

## Repository Structure

- **host/**  
  Contains Python code used to communicate with the device.

- **inc/**  
  Contains header files used throughout the project.

- **src/**  
  Contains the source code, organized into subdirectories:
  
  - **src/codec/**  
    Implements encoding/decoding functions.  
    *Note: 32-bit and 64-bit decoding (both little-endian and big-endian) are implemented using inline functions.*

  - **src/int/**  
    Contains the big-integer (big-int) implementation.

  - **src/rsa/**  
    Contains the RSA implementation, including description and encryption functions.

---

## Implemented Coutermeasures

### **1. Message and Exponent Blinding**

To protect against first-order SCA attacks, message and exponent blinding have been implemented. These countermeasures randomize the message and exponent values during RSA operations, effectively mitigating power analysis attacks.

- **Source Code:** [message_and_exp_blind.c](src/rsa/message_and_exp_blind.c)

---

### **2. Modulus Randomization**

The exponentiation algorithm ([i31_modpow2.c](src/int/i31_modpow2.c)) has been modified to incorporate modulus randomization during each iteration. This adds an additional layer of unpredictability, further protecting against side-channel leakage.

- **Source Code:** [mod_rand_pow.c](src/int/mod_rand_pow.c)

This modified algorithm is integrated into the RSA decryption process:

- **Source Code:** [modulus_randomization.c](src/rsa/modulus_randomization.c)

---

### **3. Key Randomization**

The secret key structure ([bearssl_rsa.h](inc/bearssl_rsa.h)) has been extended to include a pre-randomized key. The updated structure contains:

- The public modulus *n*,
- The public exponent *e*,
- Two random masks (*r₁* and *r₂*),
- Blinded Euler’s totient functions of the prime factors.

This pre-randomization ensures that secret key components are masked before use, protecting against both SCA and fault attacks.

- **Source Code:** [pre_randomization.c](src/rsa/pre_randomization.c)

---

### **4. Fault Injection Protection**

Fault injection countermeasure have been integrated into the SCA-protected RSA decryption algorithm to enhance robustness against hardware fault attacks.

- **FI countermeasure:** Inspired by this [paper](https://marcjoye.github.io/papers/CJ05fdtc.pdf)
  - **Source Code:** [FI-countermeasure.c](src/rsa/FI-countermeasure.c)

---

## **Current Status**

- **Message and exponent blinding:** Successfully implemented and tested.
- **Modulus randomization:** Successfully implemented and tested.
- **Key pre-randomization:** Successfully tested and integrated into the decryption flow.
- **Fault injection protection:** Initial protections added; further improvements planned.

---

## **Future Work**

- Test the implementation against a broader range of side-channel and fault injection attack scenarios.
