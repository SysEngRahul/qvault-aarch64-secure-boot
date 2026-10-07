/* Constants shared with assembly (no C syntax allowed here). */
#define SCR_NS            (1 << 0)
#define SCR_HCE           (1 << 8)
#define SCR_RW            (1 << 10)
#define SCR_RES1          ((1 << 4) | (1 << 5))
#define HCR_RW            (1 << 31)
#define SPSR_EL2H_MASKED  0x3c9      /* D A I F masked, EL2h */
#define SPSR_EL1H_MASKED  0x3c5      /* D A I F masked, EL1h */
