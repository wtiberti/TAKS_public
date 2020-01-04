#define nx_struct struct
#define nx_union union
#define dbg(mode, format, ...) ((void)0)
#define dbg_clear(mode, format, ...) ((void)0)
#define dbg_active(mode) 0
# 143 "/usr/lib/gcc/avr/9.2.0/include/stddef.h" 3
typedef int ptrdiff_t;
#line 209
typedef unsigned int size_t;
#line 321
typedef int wchar_t;
#line 426
#line 415
typedef struct __nesc_unnamed4243 {
  long long __max_align_ll __attribute((__aligned__(__alignof__(long long )))) ;
  long double __max_align_ld __attribute((__aligned__(__alignof__(long double )))) ;
} 







max_align_t;
# 8 "/usr/local/lib/ncc/deputy_nodeputy.h"
struct __nesc_attr_nonnull {
#line 8
  int dummy;
}  ;
#line 9
struct __nesc_attr_bnd {
#line 9
  void *lo, *hi;
}  ;
#line 10
struct __nesc_attr_bnd_nok {
#line 10
  void *lo, *hi;
}  ;
#line 11
struct __nesc_attr_count {
#line 11
  int n;
}  ;
#line 12
struct __nesc_attr_count_nok {
#line 12
  int n;
}  ;
#line 13
struct __nesc_attr_one {
#line 13
  int dummy;
}  ;
#line 14
struct __nesc_attr_one_nok {
#line 14
  int dummy;
}  ;
#line 15
struct __nesc_attr_dmemset {
#line 15
  int a1, a2, a3;
}  ;
#line 16
struct __nesc_attr_dmemcpy {
#line 16
  int a1, a2, a3;
}  ;
#line 17
struct __nesc_attr_nts {
#line 17
  int dummy;
}  ;
# 125 "/usr/lib/gcc/avr/9.2.0/../../../../avr/include/stdint.h" 3
typedef signed int int8_t __attribute((__mode__(__QI__))) ;
typedef unsigned int uint8_t __attribute((__mode__(__QI__))) ;
typedef signed int int16_t __attribute((__mode__(__HI__))) ;
typedef unsigned int uint16_t __attribute((__mode__(__HI__))) ;
typedef signed int int32_t __attribute((__mode__(__SI__))) ;
typedef unsigned int uint32_t __attribute((__mode__(__SI__))) ;

typedef signed int int64_t __attribute((__mode__(__DI__))) ;
typedef unsigned int uint64_t __attribute((__mode__(__DI__))) ;
#line 146
typedef int16_t intptr_t;




typedef uint16_t uintptr_t;
#line 163
typedef int8_t int_least8_t;




typedef uint8_t uint_least8_t;




typedef int16_t int_least16_t;




typedef uint16_t uint_least16_t;




typedef int32_t int_least32_t;




typedef uint32_t uint_least32_t;







typedef int64_t int_least64_t;






typedef uint64_t uint_least64_t;
#line 217
typedef int8_t int_fast8_t;




typedef uint8_t uint_fast8_t;




typedef int16_t int_fast16_t;




typedef uint16_t uint_fast16_t;




typedef int32_t int_fast32_t;




typedef uint32_t uint_fast32_t;







typedef int64_t int_fast64_t;






typedef uint64_t uint_fast64_t;
#line 277
typedef int64_t intmax_t;




typedef uint64_t uintmax_t;
# 77 "/usr/lib/gcc/avr/9.2.0/../../../../avr/include/inttypes.h" 3
typedef int32_t int_farptr_t;



typedef uint32_t uint_farptr_t;
# 281 "/usr/local/lib/ncc/nesc_nx.h"
static __inline uint8_t __nesc_ntoh_uint8(const void * source)  ;




static __inline uint8_t __nesc_hton_uint8(void * target, uint8_t value)  ;





static __inline uint8_t __nesc_ntoh_leuint8(const void * source)  ;




static __inline uint8_t __nesc_hton_leuint8(void * target, uint8_t value)  ;





static __inline int8_t __nesc_ntoh_int8(const void * source)  ;
#line 303
static __inline int8_t __nesc_hton_int8(void * target, int8_t value)  ;
#line 322
static __inline uint16_t __nesc_ntoh_leuint16(const void * source)  ;




static __inline uint16_t __nesc_hton_leuint16(void * target, uint16_t value)  ;
#line 340
static __inline uint32_t __nesc_ntoh_uint32(const void * source)  ;






static __inline uint32_t __nesc_hton_uint32(void * target, uint32_t value)  ;
#line 431
typedef struct { unsigned char nxdata[1]; } __attribute__((packed)) nx_int8_t;typedef int8_t __nesc_nxbase_nx_int8_t  ;
typedef struct { unsigned char nxdata[2]; } __attribute__((packed)) nx_int16_t;typedef int16_t __nesc_nxbase_nx_int16_t  ;
typedef struct { unsigned char nxdata[4]; } __attribute__((packed)) nx_int32_t;typedef int32_t __nesc_nxbase_nx_int32_t  ;
typedef struct { unsigned char nxdata[8]; } __attribute__((packed)) nx_int64_t;typedef int64_t __nesc_nxbase_nx_int64_t  ;
typedef struct { unsigned char nxdata[1]; } __attribute__((packed)) nx_uint8_t;typedef uint8_t __nesc_nxbase_nx_uint8_t  ;
typedef struct { unsigned char nxdata[2]; } __attribute__((packed)) nx_uint16_t;typedef uint16_t __nesc_nxbase_nx_uint16_t  ;
typedef struct { unsigned char nxdata[4]; } __attribute__((packed)) nx_uint32_t;typedef uint32_t __nesc_nxbase_nx_uint32_t  ;
typedef struct { unsigned char nxdata[8]; } __attribute__((packed)) nx_uint64_t;typedef uint64_t __nesc_nxbase_nx_uint64_t  ;


typedef struct { unsigned char nxdata[1]; } __attribute__((packed)) nxle_int8_t;typedef int8_t __nesc_nxbase_nxle_int8_t  ;
typedef struct { unsigned char nxdata[2]; } __attribute__((packed)) nxle_int16_t;typedef int16_t __nesc_nxbase_nxle_int16_t  ;
typedef struct { unsigned char nxdata[4]; } __attribute__((packed)) nxle_int32_t;typedef int32_t __nesc_nxbase_nxle_int32_t  ;
typedef struct { unsigned char nxdata[8]; } __attribute__((packed)) nxle_int64_t;typedef int64_t __nesc_nxbase_nxle_int64_t  ;
typedef struct { unsigned char nxdata[1]; } __attribute__((packed)) nxle_uint8_t;typedef uint8_t __nesc_nxbase_nxle_uint8_t  ;
typedef struct { unsigned char nxdata[2]; } __attribute__((packed)) nxle_uint16_t;typedef uint16_t __nesc_nxbase_nxle_uint16_t  ;
typedef struct { unsigned char nxdata[4]; } __attribute__((packed)) nxle_uint32_t;typedef uint32_t __nesc_nxbase_nxle_uint32_t  ;
typedef struct { unsigned char nxdata[8]; } __attribute__((packed)) nxle_uint64_t;typedef uint64_t __nesc_nxbase_nxle_uint64_t  ;
# 115 "/usr/lib/gcc/avr/9.2.0/../../../../avr/include/string.h" 3
__extension__ 


extern int memcmp(const void *arg_0x7f7cbb582cf0, const void *arg_0x7f7cbb581020, size_t arg_0x7f7cbb5812e0) __attribute((__pure__)) ;
extern void *memcpy(void *arg_0x7f7cbb581c70, const void *arg_0x7f7cbb580020, size_t arg_0x7f7cbb5802e0);



extern void *memset(void *arg_0x7f7cbb57a020, int arg_0x7f7cbb57a2a0, size_t arg_0x7f7cbb57a560);
# 73 "/usr/lib/gcc/avr/9.2.0/../../../../avr/include/stdlib.h" 3
#line 70
typedef struct __nesc_unnamed4244 {
  int quot;
  int rem;
} div_t;





#line 76
typedef struct __nesc_unnamed4245 {
  long quot;
  long rem;
} ldiv_t;


typedef int (*__compar_fn_t)(const void *arg_0x7f7cbb5550d0, const void *arg_0x7f7cbb5553d0);
#line 252
extern unsigned long strtoul(const char *__nptr, char **__endptr, int __base);
#line 374
extern int rand(void );



extern void srand(unsigned int __seed);
# 25 "/home/wtiberti/WSN/tinyos/tos/system/tos.h"
typedef uint8_t bool;
enum __nesc_unnamed4246 {
#line 26
  FALSE = 0, TRUE = 1
};
typedef nx_int8_t nx_bool;
uint16_t TOS_NODE_ID = 1;






struct __nesc_attr_atmostonce {
};
#line 37
struct __nesc_attr_atleastonce {
};
#line 38
struct __nesc_attr_exactlyonce {
};
# 244 "/usr/lib/gcc/avr/9.2.0/../../../../avr/include/avr/fuse.h" 3
#line 239
typedef struct __nesc_unnamed4247 {

  unsigned char low;
  unsigned char high;
  unsigned char extended;
} __fuse_t;
# 68 "/home/wtiberti/WSN/tinyos/tos/types/TinyError.h"
#line 51
typedef enum __nesc_unnamed4242 {
  SUCCESS = 0, 
  FAIL = 1, 
  ESIZE = 2, 
  ECANCEL = 3, 
  EOFF = 4, 
  EBUSY = 5, 
  EINVAL = 6, 
  ERETRY = 7, 
  ERESERVE = 8, 
  EALREADY = 9, 
  ENOMEM = 10, 
  ENOACK = 11, 
  ETIMEOUT = 12, 
  ESUBSYSDIS = 13, 
  EODATA = 14, 
  ELAST = 14
} error_t  ;








static inline error_t ecombine(error_t r1, error_t r2)  ;
# 88 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/atm128hardware.h"
static __inline void __nesc_enable_interrupt()  ;



static __inline void __nesc_disable_interrupt()  ;




typedef uint8_t __nesc_atomic_t;
__nesc_atomic_t __nesc_atomic_start(void );
void __nesc_atomic_end(__nesc_atomic_t original_SREG);









#line 108
__inline __nesc_atomic_t 
__nesc_atomic_start(void )   ;









#line 118
__inline void 
__nesc_atomic_end(__nesc_atomic_t original_SREG)   ;







typedef uint8_t mcu_power_t  ;


enum __nesc_unnamed4248 {
  ATM128_POWER_IDLE = 0, 
  ATM128_POWER_ADC_NR = 1, 
  ATM128_POWER_EXT_STANDBY = 2, 
  ATM128_POWER_SAVE = 3, 
  ATM128_POWER_STANDBY = 4, 
  ATM128_POWER_DOWN = 5
};


static inline mcu_power_t mcombine(mcu_power_t m1, mcu_power_t m2)  ;









typedef struct { unsigned char nxdata[4]; } __attribute__((packed)) nx_float;typedef float __nesc_nxbase_nx_float  ;
# 43 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/adc/Atm128Adc.h"
enum __nesc_unnamed4249 {
  ATM128_ADC_VREF_OFF = 0, 
  ATM128_ADC_VREF_AVCC = 1, 
  ATM128_ADC_VREF_RSVD, 
  ATM128_ADC_VREF_2_56 = 3
};


enum __nesc_unnamed4250 {
  ATM128_ADC_RIGHT_ADJUST = 0, 
  ATM128_ADC_LEFT_ADJUST = 1
};



enum __nesc_unnamed4251 {
  ATM128_ADC_SNGL_ADC0 = 0, 
  ATM128_ADC_SNGL_ADC1, 
  ATM128_ADC_SNGL_ADC2, 
  ATM128_ADC_SNGL_ADC3, 
  ATM128_ADC_SNGL_ADC4, 
  ATM128_ADC_SNGL_ADC5, 
  ATM128_ADC_SNGL_ADC6, 
  ATM128_ADC_SNGL_ADC7, 
  ATM128_ADC_DIFF_ADC00_10x, 
  ATM128_ADC_DIFF_ADC10_10x, 
  ATM128_ADC_DIFF_ADC00_200x, 
  ATM128_ADC_DIFF_ADC10_200x, 
  ATM128_ADC_DIFF_ADC22_10x, 
  ATM128_ADC_DIFF_ADC32_10x, 
  ATM128_ADC_DIFF_ADC22_200x, 
  ATM128_ADC_DIFF_ADC32_200x, 
  ATM128_ADC_DIFF_ADC01_1x, 
  ATM128_ADC_DIFF_ADC11_1x, 
  ATM128_ADC_DIFF_ADC21_1x, 
  ATM128_ADC_DIFF_ADC31_1x, 
  ATM128_ADC_DIFF_ADC41_1x, 
  ATM128_ADC_DIFF_ADC51_1x, 
  ATM128_ADC_DIFF_ADC61_1x, 
  ATM128_ADC_DIFF_ADC71_1x, 
  ATM128_ADC_DIFF_ADC02_1x, 
  ATM128_ADC_DIFF_ADC12_1x, 
  ATM128_ADC_DIFF_ADC22_1x, 
  ATM128_ADC_DIFF_ADC32_1x, 
  ATM128_ADC_DIFF_ADC42_1x, 
  ATM128_ADC_DIFF_ADC52_1x, 
  ATM128_ADC_SNGL_1_23, 
  ATM128_ADC_SNGL_GND
};







#line 94
typedef struct __nesc_unnamed4252 {

  uint8_t mux : 5;
  uint8_t adlar : 1;
  uint8_t refs : 2;
} Atm128Admux_t;




enum __nesc_unnamed4253 {
  ATM128_ADC_PRESCALE_2 = 0, 
  ATM128_ADC_PRESCALE_2b, 
  ATM128_ADC_PRESCALE_4, 
  ATM128_ADC_PRESCALE_8, 
  ATM128_ADC_PRESCALE_16, 
  ATM128_ADC_PRESCALE_32, 
  ATM128_ADC_PRESCALE_64, 
  ATM128_ADC_PRESCALE_128, 



  ATM128_ADC_PRESCALE
};


enum __nesc_unnamed4254 {
  ATM128_ADC_ENABLE_OFF = 0, 
  ATM128_ADC_ENABLE_ON
};


enum __nesc_unnamed4255 {
  ATM128_ADC_START_CONVERSION_OFF = 0, 
  ATM128_ADC_START_CONVERSION_ON
};


enum __nesc_unnamed4256 {
  ATM128_ADC_FREE_RUNNING_OFF = 0, 
  ATM128_ADC_FREE_RUNNING_ON
};


enum __nesc_unnamed4257 {
  ATM128_ADC_INT_FLAG_OFF = 0, 
  ATM128_ADC_INT_FLAG_ON
};


enum __nesc_unnamed4258 {
  ATM128_ADC_INT_ENABLE_OFF = 0, 
  ATM128_ADC_INT_ENABLE_ON
};










#line 150
typedef struct __nesc_unnamed4259 {

  uint8_t adps : 3;
  uint8_t adie : 1;
  uint8_t adif : 1;
  uint8_t adfr : 1;
  uint8_t adsc : 1;
  uint8_t aden : 1;
} Atm128Adcsra_t;

typedef uint8_t Atm128_ADCH_t;
typedef uint8_t Atm128_ADCL_t;
# 41 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.h"
typedef struct __nesc_unnamed4260 {
#line 41
  int notUsed;
} 
#line 41
TSecond;
typedef struct __nesc_unnamed4261 {
#line 42
  int notUsed;
} 
#line 42
TMilli;
typedef struct __nesc_unnamed4262 {
#line 43
  int notUsed;
} 
#line 43
T32khz;
typedef struct __nesc_unnamed4263 {
#line 44
  int notUsed;
} 
#line 44
TMicro;
# 52 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128Timer.h"
enum __nesc_unnamed4264 {
  ATM128_CLK8_OFF = 0x0, 
  ATM128_CLK8_NORMAL = 0x1, 
  ATM128_CLK8_DIVIDE_8 = 0x2, 
  ATM128_CLK8_DIVIDE_32 = 0x3, 
  ATM128_CLK8_DIVIDE_64 = 0x4, 
  ATM128_CLK8_DIVIDE_128 = 0x5, 
  ATM128_CLK8_DIVIDE_256 = 0x6, 
  ATM128_CLK8_DIVIDE_1024 = 0x7
};

enum __nesc_unnamed4265 {
  ATM128_CLK16_OFF = 0x0, 
  ATM128_CLK16_NORMAL = 0x1, 
  ATM128_CLK16_DIVIDE_8 = 0x2, 
  ATM128_CLK16_DIVIDE_64 = 0x3, 
  ATM128_CLK16_DIVIDE_256 = 0x4, 
  ATM128_CLK16_DIVIDE_1024 = 0x5, 
  ATM128_CLK16_EXTERNAL_FALL = 0x6, 
  ATM128_CLK16_EXTERNAL_RISE = 0x7
};


enum __nesc_unnamed4266 {
  AVR_CLOCK_OFF = 0, 
  AVR_CLOCK_ON = 1, 
  AVR_CLOCK_DIVIDE_8 = 2
};


enum __nesc_unnamed4267 {
  ATM128_WAVE8_NORMAL = 0, 
  ATM128_WAVE8_PWM, 
  ATM128_WAVE8_CTC, 
  ATM128_WAVE8_PWM_FAST
};


enum __nesc_unnamed4268 {
  ATM128_COMPARE_OFF = 0, 
  ATM128_COMPARE_TOGGLE, 
  ATM128_COMPARE_CLEAR, 
  ATM128_COMPARE_SET
};
#line 108
#line 98
typedef union __nesc_unnamed4269 {

  uint8_t flat;
  struct __nesc_unnamed4270 {
    uint8_t cs : 3;
    uint8_t wgm1 : 1;
    uint8_t com : 2;
    uint8_t wgm0 : 1;
    uint8_t foc : 1;
  } bits;
} Atm128TimerControl_t;

typedef Atm128TimerControl_t Atm128_TCCR0_t;
typedef uint8_t Atm128_TCNT0_t;
typedef uint8_t Atm128_OCR0_t;

typedef Atm128TimerControl_t Atm128_TCCR2_t;
typedef uint8_t Atm128_TCNT2_t;
typedef uint8_t Atm128_OCR2_t;
#line 130
#line 120
typedef union __nesc_unnamed4271 {

  uint8_t flat;
  struct __nesc_unnamed4272 {
    uint8_t tcr0ub : 1;
    uint8_t ocr0ub : 1;
    uint8_t tcn0ub : 1;
    uint8_t as0 : 1;
    uint8_t rsvd : 4;
  } bits;
} Atm128Assr_t;
#line 146
#line 133
typedef union __nesc_unnamed4273 {

  uint8_t flat;
  struct __nesc_unnamed4274 {
    uint8_t toie0 : 1;
    uint8_t ocie0 : 1;
    uint8_t toie1 : 1;
    uint8_t ocie1b : 1;
    uint8_t ocie1a : 1;
    uint8_t ticie1 : 1;
    uint8_t toie2 : 1;
    uint8_t ocie2 : 1;
  } bits;
} Atm128_TIMSK_t;
#line 163
#line 150
typedef union __nesc_unnamed4275 {

  uint8_t flat;
  struct __nesc_unnamed4276 {
    uint8_t tov0 : 1;
    uint8_t ocf0 : 1;
    uint8_t tov1 : 1;
    uint8_t ocf1b : 1;
    uint8_t ocf1a : 1;
    uint8_t icf1 : 1;
    uint8_t tov2 : 1;
    uint8_t ocf2 : 1;
  } bits;
} Atm128_TIFR_t;
#line 178
#line 167
typedef union __nesc_unnamed4277 {

  uint8_t flat;
  struct __nesc_unnamed4278 {
    uint8_t psr321 : 1;
    uint8_t psr0 : 1;
    uint8_t pud : 1;
    uint8_t acme : 1;
    uint8_t rsvd : 3;
    uint8_t tsm : 1;
  } bits;
} Atm128_SFIOR_t;






enum __nesc_unnamed4279 {
  ATM128_TIMER_COMPARE_NORMAL = 0, 
  ATM128_TIMER_COMPARE_TOGGLE, 
  ATM128_TIMER_COMPARE_CLEAR, 
  ATM128_TIMER_COMPARE_SET
};
#line 202
#line 193
typedef union __nesc_unnamed4280 {

  uint8_t flat;
  struct __nesc_unnamed4281 {
    uint8_t wgm10 : 2;
    uint8_t comC : 2;
    uint8_t comB : 2;
    uint8_t comA : 2;
  } bits;
} Atm128TimerCtrlCompare_t;


typedef Atm128TimerCtrlCompare_t Atm128_TCCR1A_t;


typedef Atm128TimerCtrlCompare_t Atm128_TCCR3A_t;


enum __nesc_unnamed4282 {
  ATM128_WAVE16_NORMAL = 0, 
  ATM128_WAVE16_PWM_8BIT, 
  ATM128_WAVE16_PWM_9BIT, 
  ATM128_WAVE16_PWM_10BIT, 
  ATM128_WAVE16_CTC_COMPARE, 
  ATM128_WAVE16_PWM_FAST_8BIT, 
  ATM128_WAVE16_PWM_FAST_9BIT, 
  ATM128_WAVE16_PWM_FAST_10BIT, 
  ATM128_WAVE16_PWM_CAPTURE_LOW, 
  ATM128_WAVE16_PWM_COMPARE_LOW, 
  ATM128_WAVE16_PWM_CAPTURE_HIGH, 
  ATM128_WAVE16_PWM_COMPARE_HIGH, 
  ATM128_WAVE16_CTC_CAPTURE, 
  ATM128_WAVE16_RESERVED, 
  ATM128_WAVE16_PWM_FAST_CAPTURE, 
  ATM128_WAVE16_PWM_FAST_COMPARE
};
#line 241
#line 231
typedef union __nesc_unnamed4283 {

  uint8_t flat;
  struct __nesc_unnamed4284 {
    uint8_t cs : 3;
    uint8_t wgm32 : 2;
    uint8_t rsvd : 1;
    uint8_t ices1 : 1;
    uint8_t icnc1 : 1;
  } bits;
} Atm128TimerCtrlCapture_t;


typedef Atm128TimerCtrlCapture_t Atm128_TCCR1B_t;


typedef Atm128TimerCtrlCapture_t Atm128_TCCR3B_t;
#line 259
#line 250
typedef union __nesc_unnamed4285 {

  uint8_t flat;
  struct __nesc_unnamed4286 {
    uint8_t rsvd : 5;
    uint8_t focC : 1;
    uint8_t focB : 1;
    uint8_t focA : 1;
  } bits;
} Atm128TimerCtrlClock_t;


typedef Atm128TimerCtrlClock_t Atm128_TCCR1C_t;


typedef Atm128TimerCtrlClock_t Atm128_TCCR3C_t;



typedef uint8_t Atm128_TCNT1H_t;
typedef uint8_t Atm128_TCNT1L_t;
typedef uint8_t Atm128_TCNT3H_t;
typedef uint8_t Atm128_TCNT3L_t;


typedef uint8_t Atm128_OCR1AH_t;
typedef uint8_t Atm128_OCR1AL_t;
typedef uint8_t Atm128_OCR1BH_t;
typedef uint8_t Atm128_OCR1BL_t;
typedef uint8_t Atm128_OCR1CH_t;
typedef uint8_t Atm128_OCR1CL_t;


typedef uint8_t Atm128_OCR3AH_t;
typedef uint8_t Atm128_OCR3AL_t;
typedef uint8_t Atm128_OCR3BH_t;
typedef uint8_t Atm128_OCR3BL_t;
typedef uint8_t Atm128_OCR3CH_t;
typedef uint8_t Atm128_OCR3CL_t;


typedef uint8_t Atm128_ICR1H_t;
typedef uint8_t Atm128_ICR1L_t;
typedef uint8_t Atm128_ICR3H_t;
typedef uint8_t Atm128_ICR3L_t;
#line 309
#line 297
typedef union __nesc_unnamed4287 {

  uint8_t flat;
  struct __nesc_unnamed4288 {
    uint8_t ocie1c : 1;
    uint8_t ocie3c : 1;
    uint8_t toie3 : 1;
    uint8_t ocie3b : 1;
    uint8_t ocie3a : 1;
    uint8_t ticie3 : 1;
    uint8_t rsvd : 2;
  } bits;
} Atm128_ETIMSK_t;
#line 324
#line 312
typedef union __nesc_unnamed4289 {

  uint8_t flat;
  struct __nesc_unnamed4290 {
    uint8_t ocf1c : 1;
    uint8_t ocf3c : 1;
    uint8_t tov3 : 1;
    uint8_t ocf3b : 1;
    uint8_t ocf3a : 1;
    uint8_t icf3 : 1;
    uint8_t rsvd : 2;
  } bits;
} Atm128_ETIFR_t;
# 51 "/home/wtiberti/WSN/tinyos/tos/platforms/mica/MicaTimer.h"
typedef struct __nesc_unnamed4291 {
} 
#line 51
T64khz;
typedef struct __nesc_unnamed4292 {
} 
#line 52
T128khz;
typedef struct __nesc_unnamed4293 {
} 
#line 53
T2mhz;
typedef struct __nesc_unnamed4294 {
} 
#line 54
T4mhz;
#line 107
typedef T32khz TOne;
typedef TMicro TThree;
typedef uint16_t counter_one_overflow_t;
typedef uint16_t counter_three_overflow_t;

enum __nesc_unnamed4295 {
  MICA_PRESCALER_ONE = ATM128_CLK16_DIVIDE_256, 
  MICA_DIVIDE_ONE_FOR_32KHZ_LOG2 = 0, 
  MICA_PRESCALER_THREE = ATM128_CLK16_DIVIDE_8, 
  MICA_DIVIDE_THREE_FOR_MICRO_LOG2 = 0, 
  EXT_STANDBY_T0_THRESHOLD = 12
};





enum __nesc_unnamed4296 {
  PLATFORM_MHZ = 8
};
# 62 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/hardware.h"
enum __nesc_unnamed4297 {
  TOS_SLEEP_NONE = ATM128_POWER_IDLE
};


enum __nesc_unnamed4298 {
  CHANNEL_THERMISTOR = ATM128_ADC_SNGL_ADC1
};


enum __nesc_unnamed4299 {
  PLATFORM_BAUDRATE = 57600L
};
# 12 "BlinkToRadio.h"
enum __nesc_unnamed4300 {
  AM_BLINKTORADIO = 6, 
  TIMER_PERIOD_MILLI = 1000
};





#line 17
typedef struct BlinkToRadioMsg {
  uint8_t payload[16];
  uint8_t mac[4];
  uint8_t kri[32];
} BlinkToRadioMsg;
# 43 "/home/wtiberti/WSN/tinyos/tos/types/Leds.h"
enum __nesc_unnamed4301 {
  LEDS_LED0 = 1 << 0, 
  LEDS_LED1 = 1 << 1, 
  LEDS_LED2 = 1 << 2, 
  LEDS_LED3 = 1 << 3, 
  LEDS_LED4 = 1 << 4, 
  LEDS_LED5 = 1 << 5, 
  LEDS_LED6 = 1 << 6, 
  LEDS_LED7 = 1 << 7
};
# 40 "/usr/lib/gcc/avr/9.2.0/include/stdarg.h" 3
typedef __builtin_va_list __gnuc_va_list;
#line 99
typedef __gnuc_va_list va_list;
# 244 "/usr/lib/gcc/avr/9.2.0/../../../../avr/include/stdio.h" 3
struct __file {
  char *buf;
  unsigned char unget;
  uint8_t flags;
#line 263
  int size;
  int len;
  int (*put)(char arg_0x7f7cbb16b8e0, struct __file *arg_0x7f7cbb16bc40);
  int (*get)(struct __file *arg_0x7f7cbb1693b0);
  void *udata;
};








typedef struct __file FILE;
#line 407
extern struct __file *__iob[];
#line 651
extern int printf(const char *__fmt, ...);
#line 950
__extension__ 
#line 950
typedef long long fpos_t;
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420.h"
typedef uint8_t cc2420_status_t;
#line 93
#line 87
typedef nx_struct security_header {
  unsigned char __nesc_filler0[1];


  nx_uint32_t frameCounter;
  nx_uint8_t keyID[1];
} __attribute__((packed)) security_header_t;
#line 113
#line 95
typedef nx_struct cc2420_header {
  nxle_uint8_t length;
  nxle_uint16_t fcf;
  nxle_uint8_t dsn;
  nxle_uint16_t destpan;
  nxle_uint16_t dest;
  nxle_uint16_t src;







  nxle_uint8_t network;


  nxle_uint8_t type;
} __attribute__((packed)) cc2420_header_t;





#line 118
typedef nx_struct cc2420_footer {
} __attribute__((packed)) cc2420_footer_t;
#line 138
#line 122
typedef nx_struct cc2420_metadata {
  nx_uint32_t timestamp;
  nx_uint16_t rxInterval;
  nx_uint8_t rssi;
  nx_uint8_t lqi;
  nx_uint8_t tx_power;
  nx_bool crc;
  nx_bool ack;
  nx_bool timesync;
} __attribute__((packed)) 






cc2420_metadata_t;





#line 141
typedef nx_struct cc2420_packet {
  cc2420_header_t packet;
  nx_uint8_t data[];
} __attribute__((packed)) cc2420_packet_t;
#line 174
enum __nesc_unnamed4302 {

  MAC_HEADER_SIZE = sizeof(cc2420_header_t ) - 1, 

  MAC_FOOTER_SIZE = sizeof(uint16_t ), 

  MAC_PACKET_SIZE = MAC_HEADER_SIZE + 80 + MAC_FOOTER_SIZE, 

  CC2420_SIZE = MAC_HEADER_SIZE + MAC_FOOTER_SIZE
};

enum cc2420_enums {
  CC2420_TIME_ACK_TURNAROUND = 7, 
  CC2420_TIME_VREN = 20, 
  CC2420_TIME_SYMBOL = 2, 
  CC2420_BACKOFF_PERIOD = 20 / CC2420_TIME_SYMBOL, 
  CC2420_MIN_BACKOFF = 20 / CC2420_TIME_SYMBOL, 
  CC2420_ACK_WAIT_DELAY = 256
};

enum cc2420_status_enums {
  CC2420_STATUS_RSSI_VALID = 1 << 1, 
  CC2420_STATUS_LOCK = 1 << 2, 
  CC2420_STATUS_TX_ACTIVE = 1 << 3, 
  CC2420_STATUS_ENC_BUSY = 1 << 4, 
  CC2420_STATUS_TX_UNDERFLOW = 1 << 5, 
  CC2420_STATUS_XOSC16M_STABLE = 1 << 6
};

enum cc2420_config_reg_enums {
  CC2420_SNOP = 0x00, 
  CC2420_SXOSCON = 0x01, 
  CC2420_STXCAL = 0x02, 
  CC2420_SRXON = 0x03, 
  CC2420_STXON = 0x04, 
  CC2420_STXONCCA = 0x05, 
  CC2420_SRFOFF = 0x06, 
  CC2420_SXOSCOFF = 0x07, 
  CC2420_SFLUSHRX = 0x08, 
  CC2420_SFLUSHTX = 0x09, 
  CC2420_SACK = 0x0a, 
  CC2420_SACKPEND = 0x0b, 
  CC2420_SRXDEC = 0x0c, 
  CC2420_STXENC = 0x0d, 
  CC2420_SAES = 0x0e, 
  CC2420_MAIN = 0x10, 
  CC2420_MDMCTRL0 = 0x11, 
  CC2420_MDMCTRL1 = 0x12, 
  CC2420_RSSI = 0x13, 
  CC2420_SYNCWORD = 0x14, 
  CC2420_TXCTRL = 0x15, 
  CC2420_RXCTRL0 = 0x16, 
  CC2420_RXCTRL1 = 0x17, 
  CC2420_FSCTRL = 0x18, 
  CC2420_SECCTRL0 = 0x19, 
  CC2420_SECCTRL1 = 0x1a, 
  CC2420_BATTMON = 0x1b, 
  CC2420_IOCFG0 = 0x1c, 
  CC2420_IOCFG1 = 0x1d, 
  CC2420_MANFIDL = 0x1e, 
  CC2420_MANFIDH = 0x1f, 
  CC2420_FSMTC = 0x20, 
  CC2420_MANAND = 0x21, 
  CC2420_MANOR = 0x22, 
  CC2420_AGCCTRL = 0x23, 
  CC2420_AGCTST0 = 0x24, 
  CC2420_AGCTST1 = 0x25, 
  CC2420_AGCTST2 = 0x26, 
  CC2420_FSTST0 = 0x27, 
  CC2420_FSTST1 = 0x28, 
  CC2420_FSTST2 = 0x29, 
  CC2420_FSTST3 = 0x2a, 
  CC2420_RXBPFTST = 0x2b, 
  CC2420_FSMSTATE = 0x2c, 
  CC2420_ADCTST = 0x2d, 
  CC2420_DACTST = 0x2e, 
  CC2420_TOPTST = 0x2f, 
  CC2420_TXFIFO = 0x3e, 
  CC2420_RXFIFO = 0x3f
};

enum cc2420_ram_addr_enums {
  CC2420_RAM_TXFIFO = 0x000, 
  CC2420_RAM_RXFIFO = 0x080, 
  CC2420_RAM_KEY0 = 0x100, 
  CC2420_RAM_RXNONCE = 0x110, 
  CC2420_RAM_SABUF = 0x120, 
  CC2420_RAM_KEY1 = 0x130, 
  CC2420_RAM_TXNONCE = 0x140, 
  CC2420_RAM_CBCSTATE = 0x150, 
  CC2420_RAM_IEEEADR = 0x160, 
  CC2420_RAM_PANID = 0x168, 
  CC2420_RAM_SHORTADR = 0x16a
};

enum cc2420_nonce_enums {
  CC2420_NONCE_BLOCK_COUNTER = 0, 
  CC2420_NONCE_KEY_SEQ_COUNTER = 2, 
  CC2420_NONCE_FRAME_COUNTER = 3, 
  CC2420_NONCE_SOURCE_ADDRESS = 7, 
  CC2420_NONCE_FLAGS = 15
};

enum cc2420_main_enums {
  CC2420_MAIN_RESETn = 15, 
  CC2420_MAIN_ENC_RESETn = 14, 
  CC2420_MAIN_DEMOD_RESETn = 13, 
  CC2420_MAIN_MOD_RESETn = 12, 
  CC2420_MAIN_FS_RESETn = 11, 
  CC2420_MAIN_XOSC16M_BYPASS = 0
};

enum cc2420_mdmctrl0_enums {
  CC2420_MDMCTRL0_RESERVED_FRAME_MODE = 13, 
  CC2420_MDMCTRL0_PAN_COORDINATOR = 12, 
  CC2420_MDMCTRL0_ADR_DECODE = 11, 
  CC2420_MDMCTRL0_CCA_HYST = 8, 
  CC2420_MDMCTRL0_CCA_MOD = 6, 
  CC2420_MDMCTRL0_AUTOCRC = 5, 
  CC2420_MDMCTRL0_AUTOACK = 4, 
  CC2420_MDMCTRL0_PREAMBLE_LENGTH = 0
};

enum cc2420_mdmctrl1_enums {
  CC2420_MDMCTRL1_CORR_THR = 6, 
  CC2420_MDMCTRL1_DEMOD_AVG_MODE = 5, 
  CC2420_MDMCTRL1_MODULATION_MODE = 4, 
  CC2420_MDMCTRL1_TX_MODE = 2, 
  CC2420_MDMCTRL1_RX_MODE = 0
};

enum cc2420_rssi_enums {
  CC2420_RSSI_CCA_THR = 8, 
  CC2420_RSSI_RSSI_VAL = 0
};

enum cc2420_syncword_enums {
  CC2420_SYNCWORD_SYNCWORD = 0
};

enum cc2420_txctrl_enums {
  CC2420_TXCTRL_TXMIXBUF_CUR = 14, 
  CC2420_TXCTRL_TX_TURNAROUND = 13, 
  CC2420_TXCTRL_TXMIX_CAP_ARRAY = 11, 
  CC2420_TXCTRL_TXMIX_CURRENT = 9, 
  CC2420_TXCTRL_PA_CURRENT = 6, 
  CC2420_TXCTRL_RESERVED = 5, 
  CC2420_TXCTRL_PA_LEVEL = 0
};

enum cc2420_rxctrl0_enums {
  CC2420_RXCTRL0_RXMIXBUF_CUR = 12, 
  CC2420_RXCTRL0_HIGH_LNA_GAIN = 10, 
  CC2420_RXCTRL0_MED_LNA_GAIN = 8, 
  CC2420_RXCTRL0_LOW_LNA_GAIN = 6, 
  CC2420_RXCTRL0_HIGH_LNA_CURRENT = 4, 
  CC2420_RXCTRL0_MED_LNA_CURRENT = 2, 
  CC2420_RXCTRL0_LOW_LNA_CURRENT = 0
};

enum cc2420_rxctrl1_enums {
  CC2420_RXCTRL1_RXBPF_LOCUR = 13, 
  CC2420_RXCTRL1_RXBPF_MIDCUR = 12, 
  CC2420_RXCTRL1_LOW_LOWGAIN = 11, 
  CC2420_RXCTRL1_MED_LOWGAIN = 10, 
  CC2420_RXCTRL1_HIGH_HGM = 9, 
  CC2420_RXCTRL1_MED_HGM = 8, 
  CC2420_RXCTRL1_LNA_CAP_ARRAY = 6, 
  CC2420_RXCTRL1_RXMIX_TAIL = 4, 
  CC2420_RXCTRL1_RXMIX_VCM = 2, 
  CC2420_RXCTRL1_RXMIX_CURRENT = 0
};

enum cc2420_rsctrl_enums {
  CC2420_FSCTRL_LOCK_THR = 14, 
  CC2420_FSCTRL_CAL_DONE = 13, 
  CC2420_FSCTRL_CAL_RUNNING = 12, 
  CC2420_FSCTRL_LOCK_LENGTH = 11, 
  CC2420_FSCTRL_LOCK_STATUS = 10, 
  CC2420_FSCTRL_FREQ = 0
};

enum cc2420_secctrl0_enums {
  CC2420_SECCTRL0_RXFIFO_PROTECTION = 9, 
  CC2420_SECCTRL0_SEC_CBC_HEAD = 8, 
  CC2420_SECCTRL0_SEC_SAKEYSEL = 7, 
  CC2420_SECCTRL0_SEC_TXKEYSEL = 6, 
  CC2420_SECCTRL0_SEC_RXKEYSEL = 5, 
  CC2420_SECCTRL0_SEC_M = 2, 
  CC2420_SECCTRL0_SEC_MODE = 0
};

enum cc2420_secctrl1_enums {
  CC2420_SECCTRL1_SEC_TXL = 8, 
  CC2420_SECCTRL1_SEC_RXL = 0
};

enum cc2420_battmon_enums {
  CC2420_BATTMON_BATT_OK = 6, 
  CC2420_BATTMON_BATTMON_EN = 5, 
  CC2420_BATTMON_BATTMON_VOLTAGE = 0
};

enum cc2420_iocfg0_enums {
  CC2420_IOCFG0_BCN_ACCEPT = 11, 
  CC2420_IOCFG0_FIFO_POLARITY = 10, 
  CC2420_IOCFG0_FIFOP_POLARITY = 9, 
  CC2420_IOCFG0_SFD_POLARITY = 8, 
  CC2420_IOCFG0_CCA_POLARITY = 7, 
  CC2420_IOCFG0_FIFOP_THR = 0
};

enum cc2420_iocfg1_enums {
  CC2420_IOCFG1_HSSD_SRC = 10, 
  CC2420_IOCFG1_SFDMUX = 5, 
  CC2420_IOCFG1_CCAMUX = 0
};

enum cc2420_manfidl_enums {
  CC2420_MANFIDL_PARTNUM = 12, 
  CC2420_MANFIDL_MANFID = 0
};

enum cc2420_manfidh_enums {
  CC2420_MANFIDH_VERSION = 12, 
  CC2420_MANFIDH_PARTNUM = 0
};

enum cc2420_fsmtc_enums {
  CC2420_FSMTC_TC_RXCHAIN2RX = 13, 
  CC2420_FSMTC_TC_SWITCH2TX = 10, 
  CC2420_FSMTC_TC_PAON2TX = 6, 
  CC2420_FSMTC_TC_TXEND2SWITCH = 3, 
  CC2420_FSMTC_TC_TXEND2PAOFF = 0
};

enum cc2420_sfdmux_enums {
  CC2420_SFDMUX_SFD = 0, 
  CC2420_SFDMUX_XOSC16M_STABLE = 24
};

enum cc2420_security_enums {
  CC2420_NO_SEC = 0, 
  CC2420_CBC_MAC = 1, 
  CC2420_CTR = 2, 
  CC2420_CCM = 3, 
  NO_SEC = 0, 
  CBC_MAC_4 = 1, 
  CBC_MAC_8 = 2, 
  CBC_MAC_16 = 3, 
  CTR = 4, 
  CCM_4 = 5, 
  CCM_8 = 6, 
  CCM_16 = 7
};


enum __nesc_unnamed4303 {

  CC2420_INVALID_TIMESTAMP = 0x80000000L
};
# 6 "/home/wtiberti/WSN/tinyos/tos/types/AM.h"
typedef nx_uint8_t nx_am_id_t;
typedef nx_uint8_t nx_am_group_t;
typedef nx_uint16_t nx_am_addr_t;

typedef uint8_t am_id_t;
typedef uint8_t am_group_t;
typedef uint16_t am_addr_t;

enum __nesc_unnamed4304 {
  AM_BROADCAST_ADDR = 0xffff
};









enum __nesc_unnamed4305 {
  TOS_AM_GROUP = 0x22, 
  TOS_AM_ADDRESS = 1
};
# 83 "/home/wtiberti/WSN/tinyos/tos/lib/serial/Serial.h"
typedef uint8_t uart_id_t;



enum __nesc_unnamed4306 {
  HDLC_FLAG_BYTE = 0x7e, 
  HDLC_CTLESC_BYTE = 0x7d
};



enum __nesc_unnamed4307 {
  AM_SERIAL_PACKET = 0, 
  TOS_SERIAL_ACTIVE_MESSAGE_ID = 0, 
  TOS_SERIAL_CC1000_ID = 1, 
  TOS_SERIAL_802_15_4_ID = 2, 
  TOS_SERIAL_UNKNOWN_ID = 255
};


enum __nesc_unnamed4308 {
  SERIAL_PROTO_ACK = 67, 
  SERIAL_PROTO_PACKET_ACK = 68, 
  SERIAL_PROTO_PACKET_NOACK = 69, 
  SERIAL_PROTO_PACKET_UNKNOWN = 255
};
#line 122
#line 110
typedef struct radio_stats {
  uint8_t version;
  uint8_t flags;
  uint8_t reserved;
  uint8_t platform;
  uint16_t MTU;
  uint16_t radio_crc_fail;
  uint16_t radio_queue_drops;
  uint16_t serial_crc_fail;
  uint16_t serial_tx_fail;
  uint16_t serial_short_packets;
  uint16_t serial_proto_drops;
} radio_stats_t;







#line 124
typedef nx_struct serial_header {
  nx_am_addr_t dest;
  nx_am_addr_t src;
  nx_uint8_t length;
  nx_am_group_t group;
  nx_am_id_t type;
} __attribute__((packed)) serial_header_t;




#line 132
typedef nx_struct serial_packet {
  serial_header_t header;
  nx_uint8_t data[];
} __attribute__((packed)) serial_packet_t;



#line 137
typedef nx_struct serial_metadata {
  nx_uint8_t ack;
} __attribute__((packed)) serial_metadata_t;
# 60 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/platform_message.h"
#line 57
typedef union message_header {
  cc2420_header_t cc2420;
  serial_header_t serial;
} message_header_t;



#line 62
typedef union message_footer {
  cc2420_footer_t cc2420;
} message_footer_t;






#line 66
typedef struct message_metadata {
  union  {
    cc2420_metadata_t cc2420_meta;
    serial_metadata_t serial_meta;
  } ;
} message_metadata_t;
# 19 "/home/wtiberti/WSN/tinyos/tos/types/message.h"
#line 14
typedef nx_struct message_t {
  nx_uint8_t header[sizeof(message_header_t )];
  nx_uint8_t data[80];
  nx_uint8_t footer[sizeof(message_footer_t )];
  nx_uint8_t metadata[sizeof(message_metadata_t )];
} __attribute__((packed)) message_t;
# 40 "/home/wtiberti/WSN/tinyos/tos/types/IeeeEui64.h"
enum __nesc_unnamed4309 {
#line 40
  IEEE_EUI64_LENGTH = 8
};


#line 42
typedef struct ieee_eui64 {
  uint8_t data[IEEE_EUI64_LENGTH];
} ieee_eui64_t;
# 49 "/home/wtiberti/WSN/tinyos/tos/types/Ieee154.h"
typedef uint16_t ieee154_panid_t;
typedef uint16_t ieee154_saddr_t;
typedef ieee_eui64_t ieee154_laddr_t;







#line 53
typedef struct __nesc_unnamed4310 {
  uint8_t ieee_mode : 2;
  union __nesc_unnamed4311 {
    ieee154_saddr_t saddr;
    ieee154_laddr_t laddr;
  } ieee_addr;
} ieee154_addr_t;
#line 100
enum __nesc_unnamed4312 {
  IEEE154_BROADCAST_ADDR = 0xffff, 
  IEEE154_BROADCAST_PAN = 0xffff, 
  IEEE154_LINK_MTU = 127
};

struct ieee154_frame_addr {
  ieee154_addr_t ieee_src;
  ieee154_addr_t ieee_dst;
  ieee154_panid_t ieee_dstpan;
};

enum __nesc_unnamed4313 {
  IEEE154_MIN_HDR_SZ = 6
};
#line 128
enum ieee154_fcf_enums {
  IEEE154_FCF_FRAME_TYPE = 0, 
  IEEE154_FCF_SECURITY_ENABLED = 3, 
  IEEE154_FCF_FRAME_PENDING = 4, 
  IEEE154_FCF_ACK_REQ = 5, 
  IEEE154_FCF_INTRAPAN = 6, 
  IEEE154_FCF_DEST_ADDR_MODE = 10, 
  IEEE154_FCF_SRC_ADDR_MODE = 14
};

enum ieee154_fcf_type_enums {
  IEEE154_TYPE_BEACON = 0, 
  IEEE154_TYPE_DATA = 1, 
  IEEE154_TYPE_ACK = 2, 
  IEEE154_TYPE_MAC_CMD = 3, 
  IEEE154_TYPE_MASK = 7
};

enum ieee154_fcf_addr_mode_enums {
  IEEE154_ADDR_NONE = 0, 
  IEEE154_ADDR_SHORT = 2, 
  IEEE154_ADDR_EXT = 3, 
  IEEE154_ADDR_MASK = 3
};
#line 163
enum __nesc_unnamed4314 {
  TOS_IEEE154_SHORT_ADDRESS = 1, 
  TOS_IEEE154_PAN_ID = 22
};
# 41 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.h"
enum __nesc_unnamed4315 {
  ATM128_SPI_CLK_DIVIDE_4 = 0, 
  ATM128_SPI_CLK_DIVIDE_16 = 1, 
  ATM128_SPI_CLK_DIVIDE_64 = 2, 
  ATM128_SPI_CLK_DIVIDE_128 = 3
};
#line 58
#line 49
typedef struct __nesc_unnamed4316 {
  uint8_t spie : 1;
  uint8_t spe : 1;
  uint8_t dord : 1;
  uint8_t mstr : 1;
  uint8_t cpol : 1;
  uint8_t cpha : 1;
  uint8_t spr : 2;
} 
Atm128SPIControl_s;



#line 59
typedef union __nesc_unnamed4317 {
  uint8_t flat;
  Atm128SPIControl_s bits;
} Atm128SPIControl_t;

typedef Atm128SPIControl_t Atm128_SPCR_t;








#line 67
typedef struct __nesc_unnamed4318 {
  uint8_t spif : 1;
  uint8_t wcol : 1;
  uint8_t rsvd : 5;
  uint8_t spi2x : 1;
} 
Atm128SPIStatus_s;



#line 74
typedef union __nesc_unnamed4319 {
  uint8_t flat;
  Atm128SPIStatus_s bits;
} Atm128SPIStatus_t;

typedef Atm128SPIStatus_t Atm128_SPSR_t;

typedef uint8_t Atm128_SPDR_t;
# 33 "/home/wtiberti/WSN/tinyos/tos/types/Resource.h"
typedef uint8_t resource_client_id_t;
# 43 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420TimeSyncMessage.h"
typedef nx_uint32_t timesync_radio_t;





#line 45
typedef nx_struct timesync_footer_t {

  nx_am_id_t type;
  timesync_radio_t timestamp;
} __attribute__((packed)) timesync_footer_t;
# 41 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/Atm128Uart.h"
typedef uint8_t Atm128_UDR0_t;
typedef uint8_t Atm128_UDR1_t;
#line 57
#line 45
typedef union __nesc_unnamed4320 {
  struct Atm128_UCSRA_t {
    uint8_t mpcm : 1;
    uint8_t u2x : 1;
    uint8_t upe : 1;
    uint8_t dor : 1;
    uint8_t fe : 1;
    uint8_t udre : 1;
    uint8_t txc : 1;
    uint8_t rxc : 1;
  } bits;
  uint8_t flat;
} Atm128UartStatus_t;

typedef Atm128UartStatus_t Atm128_UCSR0A_t;
typedef Atm128UartStatus_t Atm128_UCSR1A_t;
#line 75
#line 63
typedef union __nesc_unnamed4321 {
  struct Atm128_UCSRB_t {
    uint8_t txb8 : 1;
    uint8_t rxb8 : 1;
    uint8_t ucsz2 : 1;
    uint8_t txen : 1;
    uint8_t rxen : 1;
    uint8_t udrie : 1;
    uint8_t txcie : 1;
    uint8_t rxcie : 1;
  } bits;
  uint8_t flat;
} Atm128UartControl_t;

typedef Atm128UartControl_t Atm128_UCSR0B_t;
typedef Atm128UartControl_t Atm128_UCSR1B_t;

enum __nesc_unnamed4322 {
  ATM128_UART_DATA_SIZE_5_BITS = 0, 
  ATM128_UART_DATA_SIZE_6_BITS = 1, 
  ATM128_UART_DATA_SIZE_7_BITS = 2, 
  ATM128_UART_DATA_SIZE_8_BITS = 3
};
#line 98
#line 88
typedef union __nesc_unnamed4323 {
  uint8_t flat;
  struct Atm128_UCSRC_t {
    uint8_t ucpol : 1;
    uint8_t ucsz : 2;
    uint8_t usbs : 1;
    uint8_t upm : 2;
    uint8_t umsel : 1;
    uint8_t rsvd : 1;
  } bits;
} Atm128UartMode_t;

typedef Atm128UartMode_t Atm128_UCSR0C_t;
typedef Atm128UartMode_t Atm128_UCSR1C_t;





enum __nesc_unnamed4324 {
  ATM128_19200_BAUD_4MHZ = 12, 
  ATM128_38400_BAUD_4MHZ = 6, 
  ATM128_57600_BAUD_4MHZ = 3, 

  ATM128_19200_BAUD_4MHZ_2X = 25, 
  ATM128_38400_BAUD_4MHZ_2X = 12, 
  ATM128_57600_BAUD_4MHZ_2X = 8, 

  ATM128_19200_BAUD_7MHZ = 23, 
  ATM128_38400_BAUD_7MHZ = 11, 
  ATM128_57600_BAUD_7MHZ = 7, 

  ATM128_19200_BAUD_7MHZ_2X = 47, 
  ATM128_38400_BAUD_7MHZ_2X = 23, 
  ATM128_57600_BAUD_7MHZ_2X = 15, 

  ATM128_19200_BAUD_8MHZ = 25, 
  ATM128_38400_BAUD_8MHZ = 12, 
  ATM128_57600_BAUD_8MHZ = 8, 

  ATM128_19200_BAUD_8MHZ_2X = 51, 
  ATM128_38400_BAUD_8MHZ_2X = 34, 
  ATM128_57600_BAUD_8MHZ_2X = 11
};

typedef uint8_t Atm128_UBRR0L_t;
typedef uint8_t Atm128_UBRR0H_t;

typedef uint8_t Atm128_UBRR1L_t;
typedef uint8_t Atm128_UBRR1H_t;

typedef uint8_t uart_parity_t;
typedef uint8_t uart_speed_t;
typedef uint8_t uart_duplex_t;

enum __nesc_unnamed4325 {
  TOS_UART_PARITY_NONE = 0, 
  TOS_UART_PARITY_EVEN = 1, 
  TOS_UART_PARITY_ODD = 2
};

enum __nesc_unnamed4326 {
  TOS_UART_19200 = 0, 
  TOS_UART_38400 = 1, 
  TOS_UART_57600 = 2
};

enum __nesc_unnamed4327 {
  TOS_UART_OFF = 0, 
  TOS_UART_RONLY = 1, 
  TOS_UART_TONLY = 2, 
  TOS_UART_DUPLEX = 3
};
# 87 "/home/wtiberti/WSN/tinyos/tos/lib/printf/PutcharP.nc"
static int uart_putchar(char c, FILE *stream);
static FILE atm128_stdout = 
{ .put = (int (*)(char c, FILE *stream))uart_putchar, .get = (void *)0, .flags = 0x0002, .udata = 0 };
typedef TMilli BlinkToRadioC__Timer0__precision_tag;
enum HilTimerMilliC____nesc_unnamed4328 {
  HilTimerMilliC__TIMER_COUNT = 2U
};
typedef TMilli /*AlarmCounterMilliP.Atm128AlarmAsyncC*/Atm128AlarmAsyncC__0__precision;
typedef /*AlarmCounterMilliP.Atm128AlarmAsyncC*/Atm128AlarmAsyncC__0__precision /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__precision;
typedef /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__precision /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__precision_tag;
typedef uint32_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__size_type;
typedef /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__precision /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Counter__precision_tag;
typedef uint32_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Counter__size_type;
typedef uint8_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__size_type;
typedef uint8_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__timer_size;
typedef uint8_t HplAtm128Timer0AsyncP__Compare__size_type;
typedef uint8_t HplAtm128Timer0AsyncP__Timer__timer_size;
typedef TMilli /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__precision_tag;
typedef /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__precision_tag /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__precision_tag;
typedef uint32_t /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__size_type;
typedef /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__precision_tag /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__precision_tag;
typedef TMilli /*HilTimerMilliC.VirtualizeTimerC*/VirtualizeTimerC__0__precision_tag;
typedef /*HilTimerMilliC.VirtualizeTimerC*/VirtualizeTimerC__0__precision_tag /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__precision_tag;
typedef /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__precision_tag /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__precision_tag;
typedef /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__precision_tag /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__precision_tag;
typedef TMilli /*HilTimerMilliC.CounterToLocalTimeC*/CounterToLocalTimeC__0__precision_tag;
typedef /*HilTimerMilliC.CounterToLocalTimeC*/CounterToLocalTimeC__0__precision_tag /*HilTimerMilliC.CounterToLocalTimeC*/CounterToLocalTimeC__0__LocalTime__precision_tag;
typedef /*HilTimerMilliC.CounterToLocalTimeC*/CounterToLocalTimeC__0__precision_tag /*HilTimerMilliC.CounterToLocalTimeC*/CounterToLocalTimeC__0__Counter__precision_tag;
typedef uint32_t /*HilTimerMilliC.CounterToLocalTimeC*/CounterToLocalTimeC__0__Counter__size_type;
enum CC2420ActiveMessageC____nesc_unnamed4329 {
  CC2420ActiveMessageC__CC2420_AM_SEND_ID = 0U
};
typedef T32khz CC2420ControlP__StartupTimer__precision_tag;
typedef uint32_t CC2420ControlP__StartupTimer__size_type;
typedef uint16_t CC2420ControlP__ReadRssi__val_t;
typedef uint16_t HplAtm128Timer1P__CompareA__size_type;
typedef uint16_t HplAtm128Timer1P__Capture__size_type;
typedef uint16_t HplAtm128Timer1P__CompareB__size_type;
typedef uint16_t HplAtm128Timer1P__CompareC__size_type;
typedef uint16_t HplAtm128Timer1P__Timer__timer_size;
typedef uint16_t /*InitOneP.InitOne*/Atm128TimerInitC__0__timer_size;
typedef /*InitOneP.InitOne*/Atm128TimerInitC__0__timer_size /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__timer_size;
typedef TOne /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__frequency_tag;
typedef uint16_t /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__timer_size;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__frequency_tag /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__precision_tag;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__timer_size /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__size_type;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__timer_size /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__size_type;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__timer_size /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Timer__timer_size;
enum /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16*/AlarmOne16C__0____nesc_unnamed4330 {
  AlarmOne16C__0__COMPARE_ID = 0U
};
typedef TOne /*CounterOne16C.NCounter*/Atm128CounterC__0__frequency_tag;
typedef uint16_t /*CounterOne16C.NCounter*/Atm128CounterC__0__timer_size;
typedef /*CounterOne16C.NCounter*/Atm128CounterC__0__frequency_tag /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__precision_tag;
typedef /*CounterOne16C.NCounter*/Atm128CounterC__0__timer_size /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__size_type;
typedef /*CounterOne16C.NCounter*/Atm128CounterC__0__timer_size /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__timer_size;
typedef T32khz /*Counter32khz32C.Transform32*/TransformCounterC__0__to_precision_tag;
typedef uint32_t /*Counter32khz32C.Transform32*/TransformCounterC__0__to_size_type;
typedef TOne /*Counter32khz32C.Transform32*/TransformCounterC__0__from_precision_tag;
typedef uint16_t /*Counter32khz32C.Transform32*/TransformCounterC__0__from_size_type;
typedef counter_one_overflow_t /*Counter32khz32C.Transform32*/TransformCounterC__0__upper_count_type;
typedef /*Counter32khz32C.Transform32*/TransformCounterC__0__from_precision_tag /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__precision_tag;
typedef /*Counter32khz32C.Transform32*/TransformCounterC__0__from_size_type /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__size_type;
typedef /*Counter32khz32C.Transform32*/TransformCounterC__0__to_precision_tag /*Counter32khz32C.Transform32*/TransformCounterC__0__Counter__precision_tag;
typedef /*Counter32khz32C.Transform32*/TransformCounterC__0__to_size_type /*Counter32khz32C.Transform32*/TransformCounterC__0__Counter__size_type;
typedef T32khz /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_precision_tag;
typedef uint32_t /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type;
typedef TOne /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__from_precision_tag;
typedef uint16_t /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__from_size_type;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_precision_tag /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__precision_tag;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__size_type;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__from_precision_tag /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__precision_tag;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__from_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__size_type;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_precision_tag /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Counter__precision_tag;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Counter__size_type;
typedef uint16_t /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__size_type;
enum /*CC2420ControlC.Spi*/CC2420SpiC__0____nesc_unnamed4331 {
  CC2420SpiC__0__CLIENT_ID = 0U
};
enum /*CC2420ControlC.SyncSpiC*/CC2420SpiC__1____nesc_unnamed4332 {
  CC2420SpiC__1__CLIENT_ID = 1U
};
enum /*CC2420ControlC.RssiResource*/CC2420SpiC__2____nesc_unnamed4333 {
  CC2420SpiC__2__CLIENT_ID = 2U
};
typedef T32khz CC2420TransmitP__PacketTimeStamp__precision_tag;
typedef uint32_t CC2420TransmitP__PacketTimeStamp__size_type;
typedef T32khz CC2420TransmitP__BackoffTimer__precision_tag;
typedef uint32_t CC2420TransmitP__BackoffTimer__size_type;
enum /*CC2420TransmitC.Spi*/CC2420SpiC__3____nesc_unnamed4334 {
  CC2420SpiC__3__CLIENT_ID = 3U
};
typedef T32khz CC2420ReceiveP__PacketTimeStamp__precision_tag;
typedef uint32_t CC2420ReceiveP__PacketTimeStamp__size_type;
typedef T32khz CC2420PacketP__PacketTimeStamp32khz__precision_tag;
typedef uint32_t CC2420PacketP__PacketTimeStamp32khz__size_type;
typedef T32khz CC2420PacketP__LocalTime32khz__precision_tag;
typedef TMilli CC2420PacketP__LocalTimeMilli__precision_tag;
typedef TMilli CC2420PacketP__PacketTimeStampMilli__precision_tag;
typedef uint32_t CC2420PacketP__PacketTimeStampMilli__size_type;
typedef T32khz /*CC2420PacketC.CounterToLocalTimeC*/CounterToLocalTimeC__1__precision_tag;
typedef /*CC2420PacketC.CounterToLocalTimeC*/CounterToLocalTimeC__1__precision_tag /*CC2420PacketC.CounterToLocalTimeC*/CounterToLocalTimeC__1__LocalTime__precision_tag;
typedef /*CC2420PacketC.CounterToLocalTimeC*/CounterToLocalTimeC__1__precision_tag /*CC2420PacketC.CounterToLocalTimeC*/CounterToLocalTimeC__1__Counter__precision_tag;
typedef uint32_t /*CC2420PacketC.CounterToLocalTimeC*/CounterToLocalTimeC__1__Counter__size_type;
enum /*CC2420ReceiveC.Spi*/CC2420SpiC__4____nesc_unnamed4335 {
  CC2420SpiC__4__CLIENT_ID = 4U
};
typedef uint16_t RandomMlcgC__SeedInit__parameter;
enum CC2420TinyosNetworkC____nesc_unnamed4336 {
  CC2420TinyosNetworkC__TINYOS_N_NETWORKS = 1U
};
enum AMQueueP____nesc_unnamed4337 {
  AMQueueP__NUM_CLIENTS = 1U
};
typedef TMicro TAKSM__LocalTime__precision_tag;
typedef uint16_t HplAtm128Timer3P__CompareA__size_type;
typedef uint16_t HplAtm128Timer3P__Capture__size_type;
typedef uint16_t HplAtm128Timer3P__CompareB__size_type;
typedef uint16_t HplAtm128Timer3P__CompareC__size_type;
typedef uint16_t HplAtm128Timer3P__Timer__timer_size;
typedef uint16_t /*InitThreeP.InitThree*/Atm128TimerInitC__1__timer_size;
typedef /*InitThreeP.InitThree*/Atm128TimerInitC__1__timer_size /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__timer_size;
typedef TThree /*CounterThree16C.NCounter*/Atm128CounterC__1__frequency_tag;
typedef uint16_t /*CounterThree16C.NCounter*/Atm128CounterC__1__timer_size;
typedef /*CounterThree16C.NCounter*/Atm128CounterC__1__frequency_tag /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__precision_tag;
typedef /*CounterThree16C.NCounter*/Atm128CounterC__1__timer_size /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__size_type;
typedef /*CounterThree16C.NCounter*/Atm128CounterC__1__timer_size /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__timer_size;
typedef TMicro /*CounterMicro32C.Transform32*/TransformCounterC__1__to_precision_tag;
typedef uint32_t /*CounterMicro32C.Transform32*/TransformCounterC__1__to_size_type;
typedef TThree /*CounterMicro32C.Transform32*/TransformCounterC__1__from_precision_tag;
typedef uint16_t /*CounterMicro32C.Transform32*/TransformCounterC__1__from_size_type;
typedef counter_three_overflow_t /*CounterMicro32C.Transform32*/TransformCounterC__1__upper_count_type;
typedef /*CounterMicro32C.Transform32*/TransformCounterC__1__from_precision_tag /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__precision_tag;
typedef /*CounterMicro32C.Transform32*/TransformCounterC__1__from_size_type /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__size_type;
typedef /*CounterMicro32C.Transform32*/TransformCounterC__1__to_precision_tag /*CounterMicro32C.Transform32*/TransformCounterC__1__Counter__precision_tag;
typedef /*CounterMicro32C.Transform32*/TransformCounterC__1__to_size_type /*CounterMicro32C.Transform32*/TransformCounterC__1__Counter__size_type;
typedef TMicro /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__precision_tag;
typedef /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__precision_tag /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__LocalTime__precision_tag;
typedef /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__precision_tag /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__precision_tag;
typedef uint32_t /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__size_type;
typedef TMicro /*Atm128Uart0C.UartP*/Atm128UartP__0__Counter__precision_tag;
typedef uint32_t /*Atm128Uart0C.UartP*/Atm128UartP__0__Counter__size_type;
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t PlatformP__Init__init(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Platform.nc"
static uint32_t PlatformP__Platform__usecsRaw(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t MotePlatformP__PlatformInit__init(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void /*HplAtm128GeneralIOC.PortA.Bit0*/HplAtm128GeneralIOPinP__0__IO__makeOutput(void );
#line 40
static void /*HplAtm128GeneralIOC.PortA.Bit0*/HplAtm128GeneralIOPinP__0__IO__set(void );
static void /*HplAtm128GeneralIOC.PortA.Bit0*/HplAtm128GeneralIOPinP__0__IO__clr(void );




static void /*HplAtm128GeneralIOC.PortA.Bit1*/HplAtm128GeneralIOPinP__1__IO__makeOutput(void );
#line 40
static void /*HplAtm128GeneralIOC.PortA.Bit1*/HplAtm128GeneralIOPinP__1__IO__set(void );
static void /*HplAtm128GeneralIOC.PortA.Bit1*/HplAtm128GeneralIOPinP__1__IO__clr(void );




static void /*HplAtm128GeneralIOC.PortA.Bit2*/HplAtm128GeneralIOPinP__2__IO__makeOutput(void );
#line 40
static void /*HplAtm128GeneralIOC.PortA.Bit2*/HplAtm128GeneralIOPinP__2__IO__set(void );
static void /*HplAtm128GeneralIOC.PortA.Bit2*/HplAtm128GeneralIOPinP__2__IO__clr(void );


static void /*HplAtm128GeneralIOC.PortA.Bit4*/HplAtm128GeneralIOPinP__4__IO__makeInput(void );
#line 41
static void /*HplAtm128GeneralIOC.PortA.Bit4*/HplAtm128GeneralIOPinP__4__IO__clr(void );




static void /*HplAtm128GeneralIOC.PortA.Bit5*/HplAtm128GeneralIOPinP__5__IO__makeOutput(void );
#line 40
static void /*HplAtm128GeneralIOC.PortA.Bit5*/HplAtm128GeneralIOPinP__5__IO__set(void );
static void /*HplAtm128GeneralIOC.PortA.Bit5*/HplAtm128GeneralIOPinP__5__IO__clr(void );




static void /*HplAtm128GeneralIOC.PortA.Bit6*/HplAtm128GeneralIOPinP__6__IO__makeOutput(void );
#line 40
static void /*HplAtm128GeneralIOC.PortA.Bit6*/HplAtm128GeneralIOPinP__6__IO__set(void );
static void /*HplAtm128GeneralIOC.PortA.Bit6*/HplAtm128GeneralIOPinP__6__IO__clr(void );




static void /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__makeOutput(void );
#line 40
static void /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__set(void );
static void /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__clr(void );




static void /*HplAtm128GeneralIOC.PortB.Bit1*/HplAtm128GeneralIOPinP__9__IO__makeOutput(void );
#line 46
static void /*HplAtm128GeneralIOC.PortB.Bit2*/HplAtm128GeneralIOPinP__10__IO__makeOutput(void );
#line 44
static void /*HplAtm128GeneralIOC.PortB.Bit3*/HplAtm128GeneralIOPinP__11__IO__makeInput(void );
#line 43
static bool /*HplAtm128GeneralIOC.PortB.Bit7*/HplAtm128GeneralIOPinP__15__IO__get(void );
static void /*HplAtm128GeneralIOC.PortD.Bit4*/HplAtm128GeneralIOPinP__28__IO__makeInput(void );
#line 43
static bool /*HplAtm128GeneralIOC.PortD.Bit4*/HplAtm128GeneralIOPinP__28__IO__get(void );
static void /*HplAtm128GeneralIOC.PortD.Bit6*/HplAtm128GeneralIOPinP__30__IO__makeInput(void );
#line 43
static bool /*HplAtm128GeneralIOC.PortD.Bit6*/HplAtm128GeneralIOPinP__30__IO__get(void );
#line 43
static bool /*HplAtm128GeneralIOC.PortE.Bit6*/HplAtm128GeneralIOPinP__38__IO__get(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t MeasureClockC__Init__init(void );
# 60 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128Calibrate.nc"
static uint16_t MeasureClockC__Atm128Calibrate__baudrateRegister(uint32_t baudrate);
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t SchedulerBasicP__TaskBasic__postTask(
# 55 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
uint8_t arg_0x7f7cbb3d4de0);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void SchedulerBasicP__TaskBasic__default__runTask(
# 55 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
uint8_t arg_0x7f7cbb3d4de0);
# 57 "/home/wtiberti/WSN/tinyos/tos/interfaces/Scheduler.nc"
static void SchedulerBasicP__Scheduler__init(void );
#line 72
static void SchedulerBasicP__Scheduler__taskLoop(void );
#line 65
static bool SchedulerBasicP__Scheduler__runNextTask(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuSleep.nc"
static void McuSleepC__McuSleep__sleep(void );
# 52 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerState.nc"
static void McuSleepC__McuPowerState__update(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t LedsP__Init__init(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/Leds.nc"
static void LedsP__Leds__led0Off(void );










static void LedsP__Leds__led1On(void );




static void LedsP__Leds__led1Off(void );
#line 94
static void LedsP__Leds__led2Off(void );
#line 56
static void LedsP__Leds__led0On(void );
#line 89
static void LedsP__Leds__led2On(void );
# 83 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
static void BlinkToRadioC__Timer0__fired(void );
# 113 "/home/wtiberti/WSN/tinyos/tos/interfaces/SplitControl.nc"
static void BlinkToRadioC__AMControl__startDone(error_t error);
#line 138
static void BlinkToRadioC__AMControl__stopDone(error_t error);
# 60 "/home/wtiberti/WSN/tinyos/tos/interfaces/Boot.nc"
static void BlinkToRadioC__Boot__booted(void );
# 110 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
static void BlinkToRadioC__AMSend__sendDone(
#line 103
message_t * msg, 






error_t error);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



BlinkToRadioC__Receive__receive(
#line 71
message_t * msg, 
void * payload, 





uint8_t len);
# 109 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__size_type /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__getNow(void );
#line 103
static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__startAt(/*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__size_type t0, /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__size_type dt);
#line 116
static /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__size_type /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__getAlarm(void );
#line 73
static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__stop(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Init__init(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Counter__size_type /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Counter__get(void );
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__fired(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__overflow(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128TimerCtrl8.nc"
static Atm128_TIFR_t HplAtm128Timer0AsyncP__TimerCtrl__getInterruptFlag(void );
#line 46
static void HplAtm128Timer0AsyncP__TimerCtrl__setControl(Atm128TimerControl_t control);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerOverride.nc"
static mcu_power_t HplAtm128Timer0AsyncP__McuPowerOverride__lowestState(void );
# 44 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128TimerAsync.nc"
static int HplAtm128Timer0AsyncP__TimerAsync__compareBusy(void );
#line 32
static void HplAtm128Timer0AsyncP__TimerAsync__setTimer0Asynchronous(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static HplAtm128Timer0AsyncP__Compare__size_type HplAtm128Timer0AsyncP__Compare__get(void );





static void HplAtm128Timer0AsyncP__Compare__set(HplAtm128Timer0AsyncP__Compare__size_type t);










static void HplAtm128Timer0AsyncP__Compare__start(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static HplAtm128Timer0AsyncP__Timer__timer_size HplAtm128Timer0AsyncP__Timer__get(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__fired__runTask(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__fired(void );
# 136 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
static uint32_t /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__getNow(void );
#line 129
static void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__startOneShotAt(uint32_t t0, uint32_t dt);
#line 78
static void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__stop(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__updateFromTimer__runTask(void );
# 83 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__fired(void );
#line 83
static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__default__fired(
# 63 "/home/wtiberti/WSN/tinyos/tos/lib/timer/VirtualizeTimerImplP.nc"
uint8_t arg_0x7f7cbaececa0);
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__startPeriodic(
# 63 "/home/wtiberti/WSN/tinyos/tos/lib/timer/VirtualizeTimerImplP.nc"
uint8_t arg_0x7f7cbaececa0, 
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
uint32_t dt);
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*HilTimerMilliC.CounterToLocalTimeC*/CounterToLocalTimeC__0__Counter__overflow(void );
# 104 "/home/wtiberti/WSN/tinyos/tos/interfaces/SplitControl.nc"
static error_t CC2420CsmaP__SplitControl__start(void );
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
static void CC2420CsmaP__SubBackoff__requestInitialBackoff(message_t * msg);






static void CC2420CsmaP__SubBackoff__requestCongestionBackoff(message_t * msg);
# 73 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Transmit.nc"
static void CC2420CsmaP__CC2420Transmit__sendDone(message_t * p_msg, error_t error);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static error_t CC2420CsmaP__Send__send(
#line 67
message_t * msg, 







uint8_t len);
#line 112
static uint8_t CC2420CsmaP__Send__maxPayloadLength(void );
# 76 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Power.nc"
static void CC2420CsmaP__CC2420Power__startOscillatorDone(void );
#line 56
static void CC2420CsmaP__CC2420Power__startVRegDone(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420CsmaP__Resource__granted(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void CC2420CsmaP__sendDone_task__runTask(void );
#line 75
static void CC2420CsmaP__stopDone_task__runTask(void );
#line 75
static void CC2420CsmaP__startDone_task__runTask(void );
# 93 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Config.nc"
static bool CC2420ControlP__CC2420Config__isAddressRecognitionEnabled(void );
#line 117
static bool CC2420ControlP__CC2420Config__isAutoAckEnabled(void );
#line 112
static bool CC2420ControlP__CC2420Config__isHwAutoAckDefault(void );
#line 66
static ieee_eui64_t CC2420ControlP__CC2420Config__getExtAddr(void );




static uint16_t CC2420ControlP__CC2420Config__getShortAddr(void );
#line 54
static error_t CC2420ControlP__CC2420Config__sync(void );
#line 77
static uint16_t CC2420ControlP__CC2420Config__getPanAddr(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void CC2420ControlP__StartupTimer__fired(void );
# 63 "/home/wtiberti/WSN/tinyos/tos/interfaces/Read.nc"
static void CC2420ControlP__ReadRssi__default__readDone(error_t result, CC2420ControlP__ReadRssi__val_t val);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void CC2420ControlP__syncDone__runTask(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t CC2420ControlP__Init__init(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420ControlP__SpiResource__granted(void );
#line 102
static void CC2420ControlP__SyncResource__granted(void );
# 71 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Power.nc"
static error_t CC2420ControlP__CC2420Power__startOscillator(void );
#line 90
static error_t CC2420ControlP__CC2420Power__rxOn(void );
#line 51
static error_t CC2420ControlP__CC2420Power__startVReg(void );
#line 63
static error_t CC2420ControlP__CC2420Power__stopVReg(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void CC2420ControlP__sync__runTask(void );
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420ControlP__Resource__release(void );
#line 88
static error_t CC2420ControlP__Resource__request(void );
# 68 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
static void CC2420ControlP__InterruptCCA__fired(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420ControlP__RssiResource__granted(void );
# 50 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128TimerCtrl16.nc"
static void HplAtm128Timer1P__TimerCtrl__setCtrlCapture(Atm128TimerCtrlCapture_t control);
#line 46
static Atm128TimerCtrlCapture_t HplAtm128Timer1P__TimerCtrl__getCtrlCapture(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static void HplAtm128Timer1P__CompareA__reset(void );
#line 54
static void HplAtm128Timer1P__CompareA__set(HplAtm128Timer1P__CompareA__size_type t);










static void HplAtm128Timer1P__CompareA__start(void );


static void HplAtm128Timer1P__CompareA__stop(void );
# 88 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Capture.nc"
static void HplAtm128Timer1P__Capture__setEdge(bool up);
#line 47
static HplAtm128Timer1P__Capture__size_type HplAtm128Timer1P__Capture__get(void );
#line 64
static void HplAtm128Timer1P__Capture__reset(void );


static void HplAtm128Timer1P__Capture__start(void );


static void HplAtm128Timer1P__Capture__stop(void );
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static void HplAtm128Timer1P__CompareB__default__fired(void );
#line 58
static void HplAtm128Timer1P__CompareC__default__fired(void );
# 87 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static bool HplAtm128Timer1P__Timer__test(void );
#line 61
static HplAtm128Timer1P__Timer__timer_size HplAtm128Timer1P__Timer__get(void );
#line 104
static void HplAtm128Timer1P__Timer__setScale(uint8_t scale);
#line 67
static void HplAtm128Timer1P__Timer__set(HplAtm128Timer1P__Timer__timer_size t);










static void HplAtm128Timer1P__Timer__start(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t /*InitOneP.InitOne*/Atm128TimerInitC__0__Init__init(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static void /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__overflow(void );
# 103 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__size_type t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__size_type dt);
#line 73
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__stop(void );
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__fired(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Timer__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__size_type /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__get(void );






static bool /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__isOverflowPending(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static void /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__overflow(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__overflow(void );
#line 64
static /*Counter32khz32C.Transform32*/TransformCounterC__0__Counter__size_type /*Counter32khz32C.Transform32*/TransformCounterC__0__Counter__get(void );
# 109 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__getNow(void );
#line 103
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__size_type t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__size_type dt);
#line 66
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__start(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__size_type dt);






static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__stop(void );




static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__fired(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Counter__overflow(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t NoInitC__Init__init(void );
# 54 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
static error_t /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__captureFallingEdge(void );
#line 66
static void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__disable(void );
#line 53
static error_t /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__captureRisingEdge(void );
# 60 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Capture.nc"
static void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__captured(/*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__size_type t);
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__fired(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
static error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Interrupt__disable(void );
#line 54
static error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Interrupt__enableFallingEdge(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin0*/HplAtm128InterruptPinP__0__Irq__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
static void /*HplAtm128InterruptC.IntPin0*/HplAtm128InterruptPinP__0__IrqSignal__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin1*/HplAtm128InterruptPinP__1__Irq__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
static void /*HplAtm128InterruptC.IntPin1*/HplAtm128InterruptPinP__1__IrqSignal__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin2*/HplAtm128InterruptPinP__2__Irq__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
static void /*HplAtm128InterruptC.IntPin2*/HplAtm128InterruptPinP__2__IrqSignal__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin3*/HplAtm128InterruptPinP__3__Irq__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
static void /*HplAtm128InterruptC.IntPin3*/HplAtm128InterruptPinP__3__IrqSignal__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin4*/HplAtm128InterruptPinP__4__Irq__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
static void /*HplAtm128InterruptC.IntPin4*/HplAtm128InterruptPinP__4__IrqSignal__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin5*/HplAtm128InterruptPinP__5__Irq__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
static void /*HplAtm128InterruptC.IntPin5*/HplAtm128InterruptPinP__5__IrqSignal__fired(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__clear(void );
#line 51
static void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__disable(void );
#line 70
static void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__edge(bool low_to_high);
#line 46
static void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__enable(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
static void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__IrqSignal__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin7*/HplAtm128InterruptPinP__7__Irq__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
static void /*HplAtm128InterruptC.IntPin7*/HplAtm128InterruptPinP__7__IrqSignal__fired(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
static error_t HplCC2420InterruptsP__CCA__disable(void );
#line 53
static error_t HplCC2420InterruptsP__CCA__enableRisingEdge(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void HplCC2420InterruptsP__CCATask__runTask(void );
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
static void CC2420SpiP__SpiPacket__sendDone(
#line 81
uint8_t * txBuf, 
uint8_t * rxBuf, 





uint16_t len, 
error_t error);
# 62 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
static error_t CC2420SpiP__Fifo__continueRead(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9baa00, 
# 62 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
uint8_t * data, uint8_t length);
#line 91
static void CC2420SpiP__Fifo__default__writeDone(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9baa00, 
# 91 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
uint8_t * data, uint8_t length, error_t error);
#line 82
static cc2420_status_t CC2420SpiP__Fifo__write(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9baa00, 
# 82 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
uint8_t * data, uint8_t length);
#line 51
static cc2420_status_t CC2420SpiP__Fifo__beginRead(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9baa00, 
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
uint8_t * data, uint8_t length);
#line 71
static void CC2420SpiP__Fifo__default__readDone(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9baa00, 
# 71 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
uint8_t * data, uint8_t length, error_t error);
# 31 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/ChipSpiResource.nc"
static void CC2420SpiP__ChipSpiResource__abortRelease(void );







static error_t CC2420SpiP__ChipSpiResource__attemptRelease(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420SpiP__SpiResource__granted(void );
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Ram.nc"
static cc2420_status_t CC2420SpiP__Ram__write(
# 47 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint16_t arg_0x7f7cba9b9d10, 
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Ram.nc"
uint8_t offset, uint8_t * data, uint8_t length);
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
static cc2420_status_t CC2420SpiP__Reg__read(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9b7c00, 
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
uint16_t *data);







static cc2420_status_t CC2420SpiP__Reg__write(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9b7c00, 
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
uint16_t data);
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420SpiP__Resource__release(
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9bb660);
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420SpiP__Resource__immediateRequest(
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9bb660);
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420SpiP__Resource__request(
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9bb660);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420SpiP__Resource__default__granted(
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9bb660);
# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static bool CC2420SpiP__Resource__isOwner(
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9bb660);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void CC2420SpiP__grant__runTask(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
static cc2420_status_t CC2420SpiP__Strobe__strobe(
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9b69f0);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t StateImplP__Init__init(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
static void StateImplP__State__toIdle(
# 67 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
uint8_t arg_0x7f7cba9419c0);
# 66 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
static bool StateImplP__State__isState(
# 67 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
uint8_t arg_0x7f7cba9419c0, 
# 66 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
uint8_t myState);
#line 61
static bool StateImplP__State__isIdle(
# 67 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
uint8_t arg_0x7f7cba9419c0);
# 45 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
static error_t StateImplP__State__requestState(
# 67 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
uint8_t arg_0x7f7cba9419c0, 
# 45 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
uint8_t reqState);





static void StateImplP__State__forceState(
# 67 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
uint8_t arg_0x7f7cba9419c0, 
# 51 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
uint8_t reqState);
# 65 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void Atm128SpiP__ResourceConfigure__unconfigure(
# 95 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128SpiP.nc"
uint8_t arg_0x7f7cba911c20);
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void Atm128SpiP__ResourceConfigure__configure(
# 95 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128SpiP.nc"
uint8_t arg_0x7f7cba911c20);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void Atm128SpiP__zeroTask__runTask(void );
# 76 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
static error_t Atm128SpiP__SpiPacket__send(
#line 65
uint8_t * txBuf, 

uint8_t * rxBuf, 








uint16_t len);
# 45 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiByte.nc"
static uint8_t Atm128SpiP__SpiByte__write(uint8_t tx);
# 109 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
static void Atm128SpiP__Spi__dataReady(uint8_t data);
#line 89
static void HplAtm128SpiP__SPI__sleep(void );
#line 83
static void HplAtm128SpiP__SPI__initMaster(void );
#line 122
static void HplAtm128SpiP__SPI__setMasterBit(bool isMaster);
#line 113
static void HplAtm128SpiP__SPI__enableInterrupt(bool enabled);
#line 97
static uint8_t HplAtm128SpiP__SPI__read(void );
#line 141
static void HplAtm128SpiP__SPI__setMasterDoubleSpeed(bool on);
#line 131
static void HplAtm128SpiP__SPI__setClock(uint8_t speed);




static bool HplAtm128SpiP__SPI__isInterruptPending(void );
#line 125
static void HplAtm128SpiP__SPI__setClockPolarity(bool highWhenIdle);
#line 103
static void HplAtm128SpiP__SPI__write(uint8_t data);
#line 116
static void HplAtm128SpiP__SPI__enableSpi(bool busOn);
#line 128
static void HplAtm128SpiP__SPI__setClockPhase(bool sampleOnTrailing);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__Init__init(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
static error_t /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__enqueue(resource_client_id_t id);
#line 53
static bool /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEmpty(void );








static bool /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEnqueued(resource_client_id_t id);







static resource_client_id_t /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__dequeue(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__default__requested(
# 52 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
uint8_t arg_0x7f7cba82e0d0);
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__default__immediateRequested(
# 52 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
uint8_t arg_0x7f7cba82e0d0);
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__release(
# 51 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
uint8_t arg_0x7f7cba830df0);
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__immediateRequest(
# 51 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
uint8_t arg_0x7f7cba830df0);
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__request(
# 51 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
uint8_t arg_0x7f7cba830df0);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__default__granted(
# 51 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
uint8_t arg_0x7f7cba830df0);
# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static bool /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__isOwner(
# 51 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
uint8_t arg_0x7f7cba830df0);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__grantedTask__runTask(void );
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t HplCC2420SpiP__Resource__release(void );
#line 97
static error_t HplCC2420SpiP__Resource__immediateRequest(void );
#line 88
static error_t HplCC2420SpiP__Resource__request(void );
#line 128
static bool HplCC2420SpiP__Resource__isOwner(void );
#line 102
static void HplCC2420SpiP__SubResource__granted(void );
# 55 "/home/wtiberti/WSN/tinyos/tos/system/ActiveMessageAddressC.nc"
static am_addr_t ActiveMessageAddressC__amAddress(void );
# 50 "/home/wtiberti/WSN/tinyos/tos/interfaces/ActiveMessageAddress.nc"
static am_addr_t ActiveMessageAddressC__ActiveMessageAddress__amAddress(void );




static am_group_t ActiveMessageAddressC__ActiveMessageAddress__amGroup(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/interfaces/LocalIeeeEui64.nc"
static ieee_eui64_t LocalIeeeEui64C__LocalIeeeEui64__getId(void );
# 66 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
static void CC2420TransmitP__RadioBackoff__setCongestionBackoff(uint16_t backoffTime);
#line 60
static void CC2420TransmitP__RadioBackoff__setInitialBackoff(uint16_t backoffTime);
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
static void CC2420TransmitP__CaptureSFD__captured(uint16_t time);
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void CC2420TransmitP__BackoffTimer__fired(void );
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Receive.nc"
static void CC2420TransmitP__CC2420Receive__receive(uint8_t type, message_t * message);
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Transmit.nc"
static error_t CC2420TransmitP__Send__send(message_t * p_msg, bool useCca);
# 24 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/ChipSpiResource.nc"
static void CC2420TransmitP__ChipSpiResource__releasing(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t CC2420TransmitP__Init__init(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420TransmitP__SpiResource__granted(void );
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t CC2420TransmitP__StdControl__start(void );









static error_t CC2420TransmitP__StdControl__stop(void );
# 91 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
static void CC2420TransmitP__TXFIFO__writeDone(uint8_t * data, uint8_t length, error_t error);
#line 71
static void CC2420TransmitP__TXFIFO__readDone(uint8_t * data, uint8_t length, error_t error);
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Config.nc"
static void CC2420ReceiveP__CC2420Config__syncDone(error_t error);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void CC2420ReceiveP__receiveDone_task__runTask(void );
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Receive.nc"
static void CC2420ReceiveP__CC2420Receive__sfd_dropped(void );
#line 49
static void CC2420ReceiveP__CC2420Receive__sfd(uint32_t time);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t CC2420ReceiveP__Init__init(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420ReceiveP__SpiResource__granted(void );
# 91 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
static void CC2420ReceiveP__RXFIFO__writeDone(uint8_t * data, uint8_t length, error_t error);
#line 71
static void CC2420ReceiveP__RXFIFO__readDone(uint8_t * data, uint8_t length, error_t error);
# 68 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
static void CC2420ReceiveP__InterruptFIFOP__fired(void );
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t CC2420ReceiveP__StdControl__start(void );









static error_t CC2420ReceiveP__StdControl__stop(void );
# 77 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Packet.nc"
static void CC2420PacketP__CC2420Packet__setNetwork(message_t * p_msg, uint8_t networkId);
#line 75
static uint8_t CC2420PacketP__CC2420Packet__getNetwork(message_t * p_msg);
# 70 "/home/wtiberti/WSN/tinyos/tos/interfaces/PacketTimeStamp.nc"
static void CC2420PacketP__PacketTimeStamp32khz__clear(
#line 66
message_t * msg);
#line 78
static void CC2420PacketP__PacketTimeStamp32khz__set(
#line 73
message_t * msg, 




CC2420PacketP__PacketTimeStamp32khz__size_type value);
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
static cc2420_header_t * CC2420PacketP__CC2420PacketBody__getHeader(message_t * msg);










static cc2420_metadata_t * CC2420PacketP__CC2420PacketBody__getMetadata(message_t * msg);
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/PacketTimeSyncOffset.nc"
static uint8_t CC2420PacketP__PacketTimeSyncOffset__get(
#line 53
message_t * msg);
#line 50
static bool CC2420PacketP__PacketTimeSyncOffset__isSet(
#line 46
message_t * msg);
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*CC2420PacketC.CounterToLocalTimeC*/CounterToLocalTimeC__1__Counter__overflow(void );
# 52 "/home/wtiberti/WSN/tinyos/tos/interfaces/Random.nc"
static uint16_t RandomMlcgC__Random__rand16(void );
#line 46
static uint32_t RandomMlcgC__Random__rand32(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t RandomMlcgC__Init__init(void );
# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static void UniqueSendP__SubSend__sendDone(
#line 96
message_t * msg, 



error_t error);
#line 75
static error_t UniqueSendP__Send__send(
#line 67
message_t * msg, 







uint8_t len);
#line 112
static uint8_t UniqueSendP__Send__maxPayloadLength(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t UniqueSendP__Init__init(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



UniqueReceiveP__SubReceive__receive(
#line 71
message_t * msg, 
void * payload, 





uint8_t len);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t UniqueReceiveP__Init__init(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



UniqueReceiveP__DuplicateReceive__default__receive(
#line 71
message_t * msg, 
void * payload, 





uint8_t len);
# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static void CC2420TinyosNetworkP__SubSend__sendDone(
#line 96
message_t * msg, 



error_t error);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



CC2420TinyosNetworkP__SubReceive__receive(
#line 71
message_t * msg, 
void * payload, 





uint8_t len);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void CC2420TinyosNetworkP__grantTask__runTask(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static error_t CC2420TinyosNetworkP__ActiveSend__send(
#line 67
message_t * msg, 







uint8_t len);
#line 125
static 
#line 123
void * 

CC2420TinyosNetworkP__ActiveSend__getPayload(
#line 122
message_t * msg, 


uint8_t len);
#line 112
static uint8_t CC2420TinyosNetworkP__ActiveSend__maxPayloadLength(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



CC2420TinyosNetworkP__BareReceive__default__receive(
#line 71
message_t * msg, 
void * payload, 





uint8_t len);
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420TinyosNetworkP__Resource__release(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
uint8_t arg_0x7f7cba42a600);
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420TinyosNetworkP__Resource__immediateRequest(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
uint8_t arg_0x7f7cba42a600);
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420TinyosNetworkP__Resource__request(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
uint8_t arg_0x7f7cba42a600);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420TinyosNetworkP__Resource__default__granted(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
uint8_t arg_0x7f7cba42a600);
# 125 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static 
#line 123
void * 

CC2420TinyosNetworkP__BareSend__getPayload(
#line 122
message_t * msg, 


uint8_t len);
#line 100
static void CC2420TinyosNetworkP__BareSend__default__sendDone(
#line 96
message_t * msg, 



error_t error);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__Init__init(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
static error_t /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__enqueue(resource_client_id_t id);
#line 53
static bool /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__isEmpty(void );








static bool /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__isEnqueued(resource_client_id_t id);







static resource_client_id_t /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__dequeue(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



CC2420ActiveMessageP__SubReceive__receive(
#line 71
message_t * msg, 
void * payload, 





uint8_t len);
# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static void CC2420ActiveMessageP__SubSend__sendDone(
#line 96
message_t * msg, 



error_t error);
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Config.nc"
static void CC2420ActiveMessageP__CC2420Config__syncDone(error_t error);
# 95 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
static void CC2420ActiveMessageP__RadioBackoff__default__requestCca(
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba393700, 
# 95 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
message_t * msg);
#line 81
static void CC2420ActiveMessageP__RadioBackoff__default__requestInitialBackoff(
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba393700, 
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
message_t * msg);






static void CC2420ActiveMessageP__RadioBackoff__default__requestCongestionBackoff(
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba393700, 
# 88 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
message_t * msg);
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/SendNotifier.nc"
static void CC2420ActiveMessageP__SendNotifier__default__aboutToSend(
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba394b30, 
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/SendNotifier.nc"
am_addr_t dest, 
#line 57
message_t * msg);
# 95 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
static void CC2420ActiveMessageP__SubBackoff__requestCca(message_t * msg);
#line 81
static void CC2420ActiveMessageP__SubBackoff__requestInitialBackoff(message_t * msg);






static void CC2420ActiveMessageP__SubBackoff__requestCongestionBackoff(message_t * msg);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Packet.nc"
static uint8_t CC2420ActiveMessageP__Packet__payloadLength(
#line 74
message_t * msg);
#line 126
static 
#line 123
void * 


CC2420ActiveMessageP__Packet__getPayload(
#line 121
message_t * msg, 




uint8_t len);
#line 106
static uint8_t CC2420ActiveMessageP__Packet__maxPayloadLength(void );
#line 94
static void CC2420ActiveMessageP__Packet__setPayloadLength(
#line 90
message_t * msg, 



uint8_t len);
# 80 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
static error_t CC2420ActiveMessageP__AMSend__send(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba39bcf0, 
# 80 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
am_addr_t addr, 
#line 71
message_t * msg, 








uint8_t len);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



CC2420ActiveMessageP__Snoop__default__receive(
# 50 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba397c40, 
# 71 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
message_t * msg, 
void * payload, 





uint8_t len);
#line 78
static 
#line 74
message_t * 



CC2420ActiveMessageP__Receive__default__receive(
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba397060, 
# 71 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
message_t * msg, 
void * payload, 





uint8_t len);
# 68 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMPacket.nc"
static am_addr_t CC2420ActiveMessageP__AMPacket__address(void );









static am_addr_t CC2420ActiveMessageP__AMPacket__destination(
#line 74
message_t * amsg);
#line 103
static void CC2420ActiveMessageP__AMPacket__setDestination(
#line 99
message_t * amsg, 



am_addr_t addr);
#line 147
static am_id_t CC2420ActiveMessageP__AMPacket__type(
#line 143
message_t * amsg);
#line 162
static void CC2420ActiveMessageP__AMPacket__setType(
#line 158
message_t * amsg, 



am_id_t t);
#line 136
static bool CC2420ActiveMessageP__AMPacket__isForMe(
#line 133
message_t * amsg);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420ActiveMessageP__RadioResource__granted(void );
# 80 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
static error_t /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMSend__send(am_addr_t addr, 
#line 71
message_t * msg, 








uint8_t len);
# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static void /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__Send__sendDone(
#line 96
message_t * msg, 



error_t error);
# 110 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMSend__sendDone(
# 51 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
am_id_t arg_0x7f7cba2d0510, 
# 103 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
message_t * msg, 






error_t error);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static error_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__send(
# 47 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
uint8_t arg_0x7f7cba2d3960, 
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
message_t * msg, 







uint8_t len);
#line 100
static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__default__sendDone(
# 47 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
uint8_t arg_0x7f7cba2d3960, 
# 96 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
message_t * msg, 



error_t error);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__errorTask__runTask(void );
#line 75
static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__CancelTask__runTask(void );
# 8 "../TAKS.nc"
static int TAKSM__TAKS__Decrypt_pw(uint8_t *out_plaintext, uint8_t *ciphertext, size_t size, uint8_t *mac, uint8_t *kri, uint8_t *node_LKC);
#line 4
static void TAKSM__TAKS__ComponentFromHexString(uint8_t *data, const char *s);


static int TAKSM__TAKS__Encrypt_pw(uint8_t *out_ciphertext, uint8_t *plaintext, size_t size, uint8_t *out_mac, uint8_t *out_kri, uint8_t *src_LKC, uint8_t *src_TKC, uint8_t *dst_TKC);
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128TimerCtrl16.nc"
static Atm128_ETIFR_t HplAtm128Timer3P__TimerCtrl__getInterruptFlag(void );
#line 50
static void HplAtm128Timer3P__TimerCtrl__setCtrlCapture(Atm128TimerCtrlCapture_t control);
#line 46
static Atm128TimerCtrlCapture_t HplAtm128Timer3P__TimerCtrl__getCtrlCapture(void );
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static void HplAtm128Timer3P__CompareA__default__fired(void );
# 47 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Capture.nc"
static HplAtm128Timer3P__Capture__size_type HplAtm128Timer3P__Capture__get(void );
#line 60
static void HplAtm128Timer3P__Capture__default__captured(HplAtm128Timer3P__Capture__size_type t);
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static void HplAtm128Timer3P__CompareB__default__fired(void );
#line 58
static void HplAtm128Timer3P__CompareC__default__fired(void );
# 87 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static bool HplAtm128Timer3P__Timer__test(void );
#line 61
static HplAtm128Timer3P__Timer__timer_size HplAtm128Timer3P__Timer__get(void );
#line 104
static void HplAtm128Timer3P__Timer__setScale(uint8_t scale);
#line 67
static void HplAtm128Timer3P__Timer__set(HplAtm128Timer3P__Timer__timer_size t);










static void HplAtm128Timer3P__Timer__start(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t /*InitThreeP.InitThree*/Atm128TimerInitC__1__Init__init(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static void /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__size_type /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__get(void );






static bool /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__isOverflowPending(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static void /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__overflow(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__overflow(void );
#line 64
static /*CounterMicro32C.Transform32*/TransformCounterC__1__Counter__size_type /*CounterMicro32C.Transform32*/TransformCounterC__1__Counter__get(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/lib/timer/LocalTime.nc"
static uint32_t /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__LocalTime__get(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__overflow(void );
# 49 "/home/wtiberti/WSN/tinyos/tos/lib/printf/Putchar.nc"
static int SerialPrintfP__Putchar__putchar(int c);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t SerialPrintfP__Init__init(void );
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t SerialPrintfP__StdControl__start(void );
# 50 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartByte.nc"
static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__UartByte__send(uint8_t byte);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__Init__init(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
static void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__default__receivedByte(uint8_t byte);
#line 99
static void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__default__receiveDone(
#line 95
uint8_t * buf, 



uint16_t len, error_t error);
#line 57
static void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__default__sendDone(
#line 53
uint8_t * buf, 



uint16_t len, error_t error);
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*Atm128Uart0C.UartP*/Atm128UartP__0__Counter__overflow(void );
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
static void /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__rxDone(uint8_t data);
#line 47
static void /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__txDone(void );
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__StdControl__start(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t HplAtm128UartP__Uart0Init__init(void );
# 44 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
static bool HplAtm128UartP__HplUart0__isTxEmpty(void );
#line 42
static error_t HplAtm128UartP__HplUart0__enableRxIntr(void );
#line 41
static error_t HplAtm128UartP__HplUart0__disableTxIntr(void );

static error_t HplAtm128UartP__HplUart0__disableRxIntr(void );


static void HplAtm128UartP__HplUart0__tx(uint8_t data);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t HplAtm128UartP__Uart1Init__init(void );
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
static void HplAtm128UartP__HplUart1__default__rxDone(uint8_t data);
#line 47
static void HplAtm128UartP__HplUart1__default__txDone(void );
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t HplAtm128UartP__Uart0RxControl__start(void );
#line 95
static error_t HplAtm128UartP__Uart0TxControl__start(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t PutcharP__Init__init(void );
#line 62
static error_t PlatformP__MoteInit__init(void );
#line 62
static error_t PlatformP__MeasureClock__init(void );
# 49 "/home/wtiberti/WSN/tinyos/tos/platforms/mica/PlatformP.nc"
static inline error_t PlatformP__Init__init(void );










static inline uint32_t PlatformP__Platform__usecsRaw(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t MotePlatformP__SubInit__init(void );
# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void MotePlatformP__SerialIdPin__makeInput(void );
#line 41
static void MotePlatformP__SerialIdPin__clr(void );
# 49 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/MotePlatformP.nc"
static inline error_t MotePlatformP__PlatformInit__init(void );
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit0*/HplAtm128GeneralIOPinP__0__IO__set(void );
static __inline void /*HplAtm128GeneralIOC.PortA.Bit0*/HplAtm128GeneralIOPinP__0__IO__clr(void );




static __inline void /*HplAtm128GeneralIOC.PortA.Bit0*/HplAtm128GeneralIOPinP__0__IO__makeOutput(void );
#line 55
static __inline void /*HplAtm128GeneralIOC.PortA.Bit1*/HplAtm128GeneralIOPinP__1__IO__set(void );
static __inline void /*HplAtm128GeneralIOC.PortA.Bit1*/HplAtm128GeneralIOPinP__1__IO__clr(void );




static __inline void /*HplAtm128GeneralIOC.PortA.Bit1*/HplAtm128GeneralIOPinP__1__IO__makeOutput(void );
#line 55
static __inline void /*HplAtm128GeneralIOC.PortA.Bit2*/HplAtm128GeneralIOPinP__2__IO__set(void );
static __inline void /*HplAtm128GeneralIOC.PortA.Bit2*/HplAtm128GeneralIOPinP__2__IO__clr(void );




static __inline void /*HplAtm128GeneralIOC.PortA.Bit2*/HplAtm128GeneralIOPinP__2__IO__makeOutput(void );
#line 56
static __inline void /*HplAtm128GeneralIOC.PortA.Bit4*/HplAtm128GeneralIOPinP__4__IO__clr(void );


static __inline void /*HplAtm128GeneralIOC.PortA.Bit4*/HplAtm128GeneralIOPinP__4__IO__makeInput(void );
#line 55
static __inline void /*HplAtm128GeneralIOC.PortA.Bit5*/HplAtm128GeneralIOPinP__5__IO__set(void );
static __inline void /*HplAtm128GeneralIOC.PortA.Bit5*/HplAtm128GeneralIOPinP__5__IO__clr(void );




static __inline void /*HplAtm128GeneralIOC.PortA.Bit5*/HplAtm128GeneralIOPinP__5__IO__makeOutput(void );
#line 55
static __inline void /*HplAtm128GeneralIOC.PortA.Bit6*/HplAtm128GeneralIOPinP__6__IO__set(void );
static __inline void /*HplAtm128GeneralIOC.PortA.Bit6*/HplAtm128GeneralIOPinP__6__IO__clr(void );




static __inline void /*HplAtm128GeneralIOC.PortA.Bit6*/HplAtm128GeneralIOPinP__6__IO__makeOutput(void );
#line 55
static __inline void /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__set(void );
static __inline void /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__clr(void );




static __inline void /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__makeOutput(void );
#line 61
static __inline void /*HplAtm128GeneralIOC.PortB.Bit1*/HplAtm128GeneralIOPinP__9__IO__makeOutput(void );
#line 61
static __inline void /*HplAtm128GeneralIOC.PortB.Bit2*/HplAtm128GeneralIOPinP__10__IO__makeOutput(void );
#line 59
static __inline void /*HplAtm128GeneralIOC.PortB.Bit3*/HplAtm128GeneralIOPinP__11__IO__makeInput(void );
#line 54
static __inline bool /*HplAtm128GeneralIOC.PortB.Bit7*/HplAtm128GeneralIOPinP__15__IO__get(void );
#line 54
static __inline bool /*HplAtm128GeneralIOC.PortD.Bit4*/HplAtm128GeneralIOPinP__28__IO__get(void );




static __inline void /*HplAtm128GeneralIOC.PortD.Bit4*/HplAtm128GeneralIOPinP__28__IO__makeInput(void );
#line 54
static __inline bool /*HplAtm128GeneralIOC.PortD.Bit6*/HplAtm128GeneralIOPinP__30__IO__get(void );




static __inline void /*HplAtm128GeneralIOC.PortD.Bit6*/HplAtm128GeneralIOPinP__30__IO__makeInput(void );
#line 54
static __inline bool /*HplAtm128GeneralIOC.PortE.Bit6*/HplAtm128GeneralIOPinP__38__IO__get(void );
# 33 "/home/wtiberti/WSN/tinyos/tos/platforms/mica/MeasureClockC.nc"
enum MeasureClockC____nesc_unnamed4338 {


  MeasureClockC__MAGIC = 488 / (16 / PLATFORM_MHZ)
};

uint16_t MeasureClockC__cycles;

static inline error_t MeasureClockC__Init__init(void );
#line 120
static inline uint16_t MeasureClockC__Atm128Calibrate__baudrateRegister(uint32_t baudrate);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t RealMainP__SoftwareInit__init(void );
# 60 "/home/wtiberti/WSN/tinyos/tos/interfaces/Boot.nc"
static void RealMainP__Boot__booted(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t RealMainP__PlatformInit__init(void );
# 57 "/home/wtiberti/WSN/tinyos/tos/interfaces/Scheduler.nc"
static void RealMainP__Scheduler__init(void );
#line 72
static void RealMainP__Scheduler__taskLoop(void );
#line 65
static bool RealMainP__Scheduler__runNextTask(void );
# 72 "/home/wtiberti/WSN/tinyos/tos/system/RealMainP.nc"
int main(void )   ;
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void SchedulerBasicP__TaskBasic__runTask(
# 55 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
uint8_t arg_0x7f7cbb3d4de0);
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuSleep.nc"
static void SchedulerBasicP__McuSleep__sleep(void );
# 59 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
enum SchedulerBasicP____nesc_unnamed4339 {
  SchedulerBasicP__NUM_TASKS = 15U, 
  SchedulerBasicP__NO_TASK = 255
};

uint8_t SchedulerBasicP__m_head;
uint8_t SchedulerBasicP__m_tail;
uint8_t SchedulerBasicP__m_next[SchedulerBasicP__NUM_TASKS];
uint8_t SchedulerBasicP__lastTask;
#line 147
static inline uint32_t SchedulerBasicP__trace_usecsRaw(void );
static inline void SchedulerBasicP__trace_post_task(uint16_t num);
static inline void SchedulerBasicP__trace_task_start(uint16_t num);
static inline void SchedulerBasicP__trace_task_end(uint16_t num, uint32_t delta);










static __inline uint8_t SchedulerBasicP__popTask(void );
#line 175
static inline bool SchedulerBasicP__isWaiting(uint8_t id);



static inline bool SchedulerBasicP__pushTask(uint8_t id);
#line 194
static inline void SchedulerBasicP__Scheduler__init(void );







static bool SchedulerBasicP__Scheduler__runNextTask(void );










static inline void SchedulerBasicP__Scheduler__taskLoop(void );
#line 236
static error_t SchedulerBasicP__TaskBasic__postTask(uint8_t id);









static void SchedulerBasicP__TaskBasic__default__runTask(uint8_t id);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerOverride.nc"
static mcu_power_t McuSleepC__McuPowerOverride__lowestState(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/McuSleepC.nc"
const uint8_t __attribute((__progmem__)) McuSleepC__atm128PowerBits[ATM128_POWER_DOWN + 1] = { 
0, 
1 << 3, ((
1 << 2) | (1 << 4)) | (1 << 3), (
1 << 4) | (1 << 3), (
1 << 2) | (1 << 4), 
1 << 4 };

static inline mcu_power_t McuSleepC__getPowerState(void );
#line 103
static inline void McuSleepC__McuSleep__sleep(void );
#line 120
static inline void McuSleepC__McuPowerState__update(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void LedsP__Led0__makeOutput(void );
#line 40
static void LedsP__Led0__set(void );
static void LedsP__Led0__clr(void );




static void LedsP__Led1__makeOutput(void );
#line 40
static void LedsP__Led1__set(void );
static void LedsP__Led1__clr(void );




static void LedsP__Led2__makeOutput(void );
#line 40
static void LedsP__Led2__set(void );
static void LedsP__Led2__clr(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/system/LedsP.nc"
static inline error_t LedsP__Init__init(void );
#line 74
static inline void LedsP__Leds__led0On(void );




static inline void LedsP__Leds__led0Off(void );









static inline void LedsP__Leds__led1On(void );




static inline void LedsP__Leds__led1Off(void );









static inline void LedsP__Leds__led2On(void );




static inline void LedsP__Leds__led2Off(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
static void BlinkToRadioC__Timer0__startPeriodic(uint32_t dt);
# 104 "/home/wtiberti/WSN/tinyos/tos/interfaces/SplitControl.nc"
static error_t BlinkToRadioC__AMControl__start(void );
# 126 "/home/wtiberti/WSN/tinyos/tos/interfaces/Packet.nc"
static 
#line 123
void * 


BlinkToRadioC__Packet__getPayload(
#line 121
message_t * msg, 




uint8_t len);
# 80 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
static error_t BlinkToRadioC__AMSend__send(am_addr_t addr, 
#line 71
message_t * msg, 








uint8_t len);
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/Leds.nc"
static void BlinkToRadioC__Leds__led0Off(void );










static void BlinkToRadioC__Leds__led1On(void );




static void BlinkToRadioC__Leds__led1Off(void );
#line 94
static void BlinkToRadioC__Leds__led2Off(void );
#line 56
static void BlinkToRadioC__Leds__led0On(void );
#line 89
static void BlinkToRadioC__Leds__led2On(void );
# 8 "../TAKS.nc"
static int BlinkToRadioC__TAKS__Decrypt_pw(uint8_t *out_plaintext, uint8_t *ciphertext, size_t size, uint8_t *mac, uint8_t *kri, uint8_t *node_LKC);
#line 4
static void BlinkToRadioC__TAKS__ComponentFromHexString(uint8_t *data, const char *s);


static int BlinkToRadioC__TAKS__Encrypt_pw(uint8_t *out_ciphertext, uint8_t *plaintext, size_t size, uint8_t *out_mac, uint8_t *out_kri, uint8_t *src_LKC, uint8_t *src_TKC, uint8_t *dst_TKC);
# 18 "BlinkToRadioC.nc"
uint16_t BlinkToRadioC__counter;
message_t BlinkToRadioC__pkt;
bool BlinkToRadioC__busy = FALSE;

uint8_t BlinkToRadioC__LKC[32];
uint8_t BlinkToRadioC__sTKC[32];
uint8_t BlinkToRadioC__dTKC[32];

static inline void BlinkToRadioC__setLeds(uint16_t val);
#line 41
static inline void BlinkToRadioC__Boot__booted(void );
#line 58
static inline void BlinkToRadioC__AMControl__startDone(error_t err);









static inline void BlinkToRadioC__AMControl__stopDone(error_t err);


static inline void BlinkToRadioC__Timer0__fired(void );
#line 97
static inline void BlinkToRadioC__AMSend__sendDone(message_t *msg, error_t err);





static inline message_t *BlinkToRadioC__Receive__receive(message_t *msg, void *payload, uint8_t len);
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128TimerCtrl8.nc"
static Atm128_TIFR_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerCtrl__getInterruptFlag(void );
#line 46
static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerCtrl__setControl(Atm128TimerControl_t control);
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__fired(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Counter__overflow(void );
# 44 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128TimerAsync.nc"
static int /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerAsync__compareBusy(void );
#line 32
static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerAsync__setTimer0Asynchronous(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__size_type /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__get(void );





static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__set(/*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__size_type t);










static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__start(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__timer_size /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__get(void );
# 38 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmAsyncP.nc"
uint8_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__set;
uint32_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__t0;
#line 39
uint32_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__dt;
uint32_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__base;



enum /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0____nesc_unnamed4340 {
  Atm128AlarmAsyncP__0__MINDT = 2, 
  Atm128AlarmAsyncP__0__MAXT = 230
};



static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__setInterrupt(void );


static inline error_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Init__init(void );
#line 74
static inline void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__setOcr0(uint8_t n);
#line 90
static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__setInterrupt(void );
#line 149
static inline void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__fired(void );
#line 161
static uint32_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Counter__get(void );
#line 204
static inline void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__stop(void );







static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__startAt(uint32_t nt0, uint32_t ndt);









static inline uint32_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__getNow(void );



static inline uint32_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__getAlarm(void );



static inline void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__overflow(void );
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static void HplAtm128Timer0AsyncP__Compare__fired(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static void HplAtm128Timer0AsyncP__Timer__overflow(void );
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer0AsyncP.nc"
static inline uint8_t HplAtm128Timer0AsyncP__Timer__get(void );
#line 85
static inline void HplAtm128Timer0AsyncP__TimerCtrl__setControl(Atm128TimerControl_t x);
#line 103
static inline Atm128_TIFR_t HplAtm128Timer0AsyncP__TimerCtrl__getInterruptFlag(void );
#line 131
static inline void HplAtm128Timer0AsyncP__Compare__start(void );









static inline uint8_t HplAtm128Timer0AsyncP__Compare__get(void );


static inline void HplAtm128Timer0AsyncP__Compare__set(uint8_t t);




static __inline void HplAtm128Timer0AsyncP__stabiliseTimer0(void );
#line 164
static inline mcu_power_t HplAtm128Timer0AsyncP__McuPowerOverride__lowestState(void );
#line 187
void __vector_15(void ) __attribute((signal))   ;





void __vector_16(void ) __attribute((signal))   ;
#line 207
static inline void HplAtm128Timer0AsyncP__TimerAsync__setTimer0Asynchronous(void );







static inline int HplAtm128Timer0AsyncP__TimerAsync__compareBusy(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__fired__postTask(void );
# 109 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__size_type /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__getNow(void );
#line 103
static void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__startAt(/*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__size_type t0, /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__size_type dt);
#line 116
static /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__size_type /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__getAlarm(void );
#line 73
static void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__stop(void );
# 83 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
static void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__fired(void );
# 74 "/home/wtiberti/WSN/tinyos/tos/lib/timer/AlarmToTimerC.nc"
enum /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0____nesc_unnamed4341 {
#line 74
  AlarmToTimerC__0__fired = 0U
};
#line 74
typedef int /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0____nesc_sillytask_fired[/*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__fired];
#line 55
uint32_t /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__m_dt;
bool /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__m_oneshot;

static inline void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__start(uint32_t t0, uint32_t dt, bool oneshot);
#line 71
static inline void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__stop(void );


static inline void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__fired__runTask(void );






static inline void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__fired(void );
#line 93
static inline void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__startOneShotAt(uint32_t t0, uint32_t dt);


static inline uint32_t /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__getNow(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__updateFromTimer__postTask(void );
# 136 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
static uint32_t /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__getNow(void );
#line 129
static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__startOneShotAt(uint32_t t0, uint32_t dt);
#line 78
static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__stop(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Platform.nc"
static uint32_t /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Platform__usecsRaw(void );
# 83 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__fired(
# 63 "/home/wtiberti/WSN/tinyos/tos/lib/timer/VirtualizeTimerImplP.nc"
uint8_t arg_0x7f7cbaececa0);
#line 153
enum /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0____nesc_unnamed4342 {
#line 153
  VirtualizeTimerImplP__0__updateFromTimer = 1U
};
#line 153
typedef int /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0____nesc_sillytask_updateFromTimer[/*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__updateFromTimer];
#line 72
enum /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0____nesc_unnamed4343 {
  VirtualizeTimerImplP__0__NUM_TIMERS = 2, 
  VirtualizeTimerImplP__0__END_OF_LIST = 255
};








#line 77
typedef struct /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0____nesc_unnamed4344 {
  uint32_t t0;
  uint32_t dt;
  uint32_t fired_max_us;
  bool isoneshot : 1;
  bool isrunning : 1;
  bool _reserved : 6;
} /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer_t;

/*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer_t /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__m_timers[/*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__NUM_TIMERS];
#line 142
static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__trace_start_timer(uint16_t num);
static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__trace_timer_fired(uint16_t num);


static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__trace_timer_end(uint16_t num, uint32_t delta);








static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__fireTimers(uint32_t now);
#line 184
static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__updateFromTimer__runTask(void );
#line 227
static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__fired(void );



static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__startTimer(uint8_t num, uint32_t t0, uint32_t dt, bool isoneshot);










static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__startPeriodic(uint8_t num, uint32_t dt);
#line 283
static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__default__fired(uint8_t num);
# 58 "/home/wtiberti/WSN/tinyos/tos/lib/timer/CounterToLocalTimeC.nc"
static inline void /*HilTimerMilliC.CounterToLocalTimeC*/CounterToLocalTimeC__0__Counter__overflow(void );
# 113 "/home/wtiberti/WSN/tinyos/tos/interfaces/SplitControl.nc"
static void CC2420CsmaP__SplitControl__startDone(error_t error);
#line 138
static void CC2420CsmaP__SplitControl__stopDone(error_t error);
# 95 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
static void CC2420CsmaP__RadioBackoff__requestCca(message_t * msg);
#line 81
static void CC2420CsmaP__RadioBackoff__requestInitialBackoff(message_t * msg);






static void CC2420CsmaP__RadioBackoff__requestCongestionBackoff(message_t * msg);
#line 66
static void CC2420CsmaP__SubBackoff__setCongestionBackoff(uint16_t backoffTime);
#line 60
static void CC2420CsmaP__SubBackoff__setInitialBackoff(uint16_t backoffTime);
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Transmit.nc"
static error_t CC2420CsmaP__CC2420Transmit__send(message_t * p_msg, bool useCca);
# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static void CC2420CsmaP__Send__sendDone(
#line 96
message_t * msg, 



error_t error);
# 52 "/home/wtiberti/WSN/tinyos/tos/interfaces/Random.nc"
static uint16_t CC2420CsmaP__Random__rand16(void );
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t CC2420CsmaP__SubControl__start(void );









static error_t CC2420CsmaP__SubControl__stop(void );
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
static cc2420_header_t * CC2420CsmaP__CC2420PacketBody__getHeader(message_t * msg);










static cc2420_metadata_t * CC2420CsmaP__CC2420PacketBody__getMetadata(message_t * msg);
# 71 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Power.nc"
static error_t CC2420CsmaP__CC2420Power__startOscillator(void );
#line 90
static error_t CC2420CsmaP__CC2420Power__rxOn(void );
#line 51
static error_t CC2420CsmaP__CC2420Power__startVReg(void );
#line 63
static error_t CC2420CsmaP__CC2420Power__stopVReg(void );
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420CsmaP__Resource__release(void );
#line 88
static error_t CC2420CsmaP__Resource__request(void );
# 66 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
static bool CC2420CsmaP__SplitControlState__isState(uint8_t myState);
#line 45
static error_t CC2420CsmaP__SplitControlState__requestState(uint8_t reqState);





static void CC2420CsmaP__SplitControlState__forceState(uint8_t reqState);
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t CC2420CsmaP__sendDone_task__postTask(void );
#line 67
static error_t CC2420CsmaP__stopDone_task__postTask(void );
#line 67
static error_t CC2420CsmaP__startDone_task__postTask(void );
# 74 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
enum CC2420CsmaP____nesc_unnamed4345 {
#line 74
  CC2420CsmaP__startDone_task = 2U
};
#line 74
typedef int CC2420CsmaP____nesc_sillytask_startDone_task[CC2420CsmaP__startDone_task];
enum CC2420CsmaP____nesc_unnamed4346 {
#line 75
  CC2420CsmaP__stopDone_task = 3U
};
#line 75
typedef int CC2420CsmaP____nesc_sillytask_stopDone_task[CC2420CsmaP__stopDone_task];
enum CC2420CsmaP____nesc_unnamed4347 {
#line 76
  CC2420CsmaP__sendDone_task = 4U
};
#line 76
typedef int CC2420CsmaP____nesc_sillytask_sendDone_task[CC2420CsmaP__sendDone_task];
#line 58
enum CC2420CsmaP____nesc_unnamed4348 {
  CC2420CsmaP__S_STOPPED, 
  CC2420CsmaP__S_STARTING, 
  CC2420CsmaP__S_STARTED, 
  CC2420CsmaP__S_STOPPING, 
  CC2420CsmaP__S_TRANSMITTING
};

message_t * CC2420CsmaP__m_msg;

error_t CC2420CsmaP__sendErr = SUCCESS;


bool CC2420CsmaP__ccaOn;






static inline void CC2420CsmaP__shutdown(void );


static error_t CC2420CsmaP__SplitControl__start(void );
#line 122
static inline error_t CC2420CsmaP__Send__send(message_t *p_msg, uint8_t len);
#line 173
static inline uint8_t CC2420CsmaP__Send__maxPayloadLength(void );
#line 205
static inline void CC2420CsmaP__CC2420Transmit__sendDone(message_t *p_msg, error_t err);




static inline void CC2420CsmaP__CC2420Power__startVRegDone(void );



static inline void CC2420CsmaP__Resource__granted(void );



static inline void CC2420CsmaP__CC2420Power__startOscillatorDone(void );




static inline void CC2420CsmaP__SubBackoff__requestInitialBackoff(message_t *msg);






static inline void CC2420CsmaP__SubBackoff__requestCongestionBackoff(message_t *msg);
#line 244
static inline void CC2420CsmaP__sendDone_task__runTask(void );
#line 257
static inline void CC2420CsmaP__startDone_task__runTask(void );







static inline void CC2420CsmaP__stopDone_task__runTask(void );









static inline void CC2420CsmaP__shutdown(void );
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Config.nc"
static void CC2420ControlP__CC2420Config__syncDone(error_t error);
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
static cc2420_status_t CC2420ControlP__RXCTRL1__write(uint16_t data);
# 48 "/home/wtiberti/WSN/tinyos/tos/interfaces/LocalIeeeEui64.nc"
static ieee_eui64_t CC2420ControlP__LocalIeeeEui64__getId(void );
# 66 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void CC2420ControlP__StartupTimer__start(CC2420ControlP__StartupTimer__size_type dt);
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
static cc2420_status_t CC2420ControlP__MDMCTRL0__write(uint16_t data);
# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void CC2420ControlP__RSTN__makeOutput(void );
#line 40
static void CC2420ControlP__RSTN__set(void );
static void CC2420ControlP__RSTN__clr(void );
# 63 "/home/wtiberti/WSN/tinyos/tos/interfaces/Read.nc"
static void CC2420ControlP__ReadRssi__readDone(error_t result, CC2420ControlP__ReadRssi__val_t val);
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t CC2420ControlP__syncDone__postTask(void );
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
static cc2420_status_t CC2420ControlP__RSSI__read(uint16_t *data);







static cc2420_status_t CC2420ControlP__TXCTRL__write(uint16_t data);
#line 63
static cc2420_status_t CC2420ControlP__IOCFG0__write(uint16_t data);
# 50 "/home/wtiberti/WSN/tinyos/tos/interfaces/ActiveMessageAddress.nc"
static am_addr_t CC2420ControlP__ActiveMessageAddress__amAddress(void );




static am_group_t CC2420ControlP__ActiveMessageAddress__amGroup(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void CC2420ControlP__CSN__makeOutput(void );
#line 40
static void CC2420ControlP__CSN__set(void );
static void CC2420ControlP__CSN__clr(void );




static void CC2420ControlP__VREN__makeOutput(void );
#line 40
static void CC2420ControlP__VREN__set(void );
static void CC2420ControlP__VREN__clr(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
static cc2420_status_t CC2420ControlP__SXOSCON__strobe(void );
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420ControlP__SpiResource__release(void );
#line 88
static error_t CC2420ControlP__SpiResource__request(void );
#line 120
static error_t CC2420ControlP__SyncResource__release(void );
#line 88
static error_t CC2420ControlP__SyncResource__request(void );
# 76 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Power.nc"
static void CC2420ControlP__CC2420Power__startOscillatorDone(void );
#line 56
static void CC2420ControlP__CC2420Power__startVRegDone(void );
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
static cc2420_status_t CC2420ControlP__IOCFG1__write(uint16_t data);
#line 63
static cc2420_status_t CC2420ControlP__FSCTRL__write(uint16_t data);
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
static cc2420_status_t CC2420ControlP__SRXON__strobe(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420ControlP__Resource__granted(void );
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Ram.nc"
static cc2420_status_t CC2420ControlP__IEEEADR__write(uint8_t offset, uint8_t * data, uint8_t length);
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
static error_t CC2420ControlP__InterruptCCA__disable(void );
#line 53
static error_t CC2420ControlP__InterruptCCA__enableRisingEdge(void );
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420ControlP__RssiResource__release(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
static cc2420_status_t CC2420ControlP__SRFOFF__strobe(void );
# 125 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
enum CC2420ControlP____nesc_unnamed4349 {
#line 125
  CC2420ControlP__sync = 5U
};
#line 125
typedef int CC2420ControlP____nesc_sillytask_sync[CC2420ControlP__sync];
enum CC2420ControlP____nesc_unnamed4350 {
#line 126
  CC2420ControlP__syncDone = 6U
};
#line 126
typedef int CC2420ControlP____nesc_sillytask_syncDone[CC2420ControlP__syncDone];
#line 90
#line 84
typedef enum CC2420ControlP____nesc_unnamed4351 {
  CC2420ControlP__S_VREG_STOPPED, 
  CC2420ControlP__S_VREG_STARTING, 
  CC2420ControlP__S_VREG_STARTED, 
  CC2420ControlP__S_XOSC_STARTING, 
  CC2420ControlP__S_XOSC_STARTED
} CC2420ControlP__cc2420_control_state_t;

uint8_t CC2420ControlP__m_channel;

uint8_t CC2420ControlP__m_tx_power;

uint16_t CC2420ControlP__m_pan;

uint16_t CC2420ControlP__m_short_addr;

ieee_eui64_t CC2420ControlP__m_ext_addr;

bool CC2420ControlP__m_sync_busy;


bool CC2420ControlP__autoAckEnabled;


bool CC2420ControlP__hwAutoAckDefault;


bool CC2420ControlP__addressRecognition;


bool CC2420ControlP__hwAddressRecognition;

CC2420ControlP__cc2420_control_state_t CC2420ControlP__m_state = CC2420ControlP__S_VREG_STOPPED;



static void CC2420ControlP__writeFsctrl(void );
static void CC2420ControlP__writeMdmctrl0(void );
static void CC2420ControlP__writeId(void );
static inline void CC2420ControlP__writeTxctrl(void );





static inline error_t CC2420ControlP__Init__init(void );
#line 188
static inline error_t CC2420ControlP__Resource__request(void );







static inline error_t CC2420ControlP__Resource__release(void );







static inline error_t CC2420ControlP__CC2420Power__startVReg(void );
#line 216
static inline error_t CC2420ControlP__CC2420Power__stopVReg(void );







static inline error_t CC2420ControlP__CC2420Power__startOscillator(void );
#line 268
static inline error_t CC2420ControlP__CC2420Power__rxOn(void );
#line 298
static inline ieee_eui64_t CC2420ControlP__CC2420Config__getExtAddr(void );



static uint16_t CC2420ControlP__CC2420Config__getShortAddr(void );







static inline uint16_t CC2420ControlP__CC2420Config__getPanAddr(void );
#line 323
static inline error_t CC2420ControlP__CC2420Config__sync(void );
#line 355
static inline bool CC2420ControlP__CC2420Config__isAddressRecognitionEnabled(void );
#line 382
static inline bool CC2420ControlP__CC2420Config__isHwAutoAckDefault(void );






static inline bool CC2420ControlP__CC2420Config__isAutoAckEnabled(void );









static inline void CC2420ControlP__SyncResource__granted(void );
#line 413
static inline void CC2420ControlP__SpiResource__granted(void );




static inline void CC2420ControlP__RssiResource__granted(void );
#line 431
static inline void CC2420ControlP__StartupTimer__fired(void );









static inline void CC2420ControlP__InterruptCCA__fired(void );
#line 465
static inline void CC2420ControlP__sync__runTask(void );



static inline void CC2420ControlP__syncDone__runTask(void );









static void CC2420ControlP__writeFsctrl(void );
#line 496
static void CC2420ControlP__writeMdmctrl0(void );
#line 515
static void CC2420ControlP__writeId(void );
#line 533
static inline void CC2420ControlP__writeTxctrl(void );
#line 545
static inline void CC2420ControlP__ReadRssi__default__readDone(error_t error, uint16_t data);
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128TimerCtrl8.nc"
static Atm128_TIFR_t HplAtm128Timer1P__Timer0Ctrl__getInterruptFlag(void );
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static void HplAtm128Timer1P__CompareA__fired(void );
# 60 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Capture.nc"
static void HplAtm128Timer1P__Capture__captured(HplAtm128Timer1P__Capture__size_type t);
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static void HplAtm128Timer1P__CompareB__fired(void );
#line 58
static void HplAtm128Timer1P__CompareC__fired(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static void HplAtm128Timer1P__Timer__overflow(void );
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline uint16_t HplAtm128Timer1P__Timer__get(void );


static inline void HplAtm128Timer1P__Timer__set(uint16_t t);








static inline void HplAtm128Timer1P__Timer__setScale(uint8_t s);









static inline Atm128TimerCtrlCapture_t HplAtm128Timer1P__TimerCtrl__getCtrlCapture(void );









static inline uint16_t HplAtm128Timer1P__TimerCtrlCapture2int(Atm128TimerCtrlCapture_t x);






static inline void HplAtm128Timer1P__TimerCtrl__setCtrlCapture(Atm128_TCCR1B_t x);
#line 131
static inline void HplAtm128Timer1P__Capture__setEdge(bool up);



static inline void HplAtm128Timer1P__Capture__reset(void );
static inline void HplAtm128Timer1P__CompareA__reset(void );



static inline void HplAtm128Timer1P__Timer__start(void );
static inline void HplAtm128Timer1P__Capture__start(void );
static inline void HplAtm128Timer1P__CompareA__start(void );




static inline void HplAtm128Timer1P__Capture__stop(void );
static inline void HplAtm128Timer1P__CompareA__stop(void );




static inline bool HplAtm128Timer1P__Timer__test(void );
#line 192
static inline void HplAtm128Timer1P__CompareA__set(uint16_t t);




static inline uint16_t HplAtm128Timer1P__Capture__get(void );






void __vector_12(void ) __attribute((interrupt))   ;


static inline void HplAtm128Timer1P__CompareB__default__fired(void );
void __vector_13(void ) __attribute((interrupt))   ;


static inline void HplAtm128Timer1P__CompareC__default__fired(void );
void __vector_24(void ) __attribute((interrupt))   ;



void __vector_11(void ) __attribute((interrupt))   ;



void __vector_14(void ) __attribute((interrupt))   ;
# 104 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static void /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__setScale(uint8_t scale);
#line 67
static void /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__set(/*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__timer_size t);










static void /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__start(void );
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128TimerInitC.nc"
static inline error_t /*InitOneP.InitOne*/Atm128TimerInitC__0__Init__init(void );








static inline void /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__overflow(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__fired(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__reset(void );
#line 54
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__set(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__size_type t);










static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__start(void );


static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__stop(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Timer__timer_size /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Timer__get(void );
# 74 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__stop(void );








static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__timer_size t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__timer_size dt);
#line 119
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__fired(void );





static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Timer__overflow(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__overflow(void );
# 87 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static bool /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__test(void );
#line 61
static /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__timer_size /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__get(void );
# 50 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128CounterC.nc"
static inline /*CounterOne16C.NCounter*/Atm128CounterC__0__timer_size /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__get(void );




static inline bool /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__isOverflowPending(void );









static inline void /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__size_type /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__get(void );






static bool /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__isOverflowPending(void );










static void /*Counter32khz32C.Transform32*/TransformCounterC__0__Counter__overflow(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
/*Counter32khz32C.Transform32*/TransformCounterC__0__upper_count_type /*Counter32khz32C.Transform32*/TransformCounterC__0__m_upper;

enum /*Counter32khz32C.Transform32*/TransformCounterC__0____nesc_unnamed4352 {

  TransformCounterC__0__LOW_SHIFT_RIGHT = 0, 
  TransformCounterC__0__HIGH_SHIFT_LEFT = 8 * sizeof(/*Counter32khz32C.Transform32*/TransformCounterC__0__from_size_type ) - /*Counter32khz32C.Transform32*/TransformCounterC__0__LOW_SHIFT_RIGHT, 
  TransformCounterC__0__NUM_UPPER_BITS = 8 * sizeof(/*Counter32khz32C.Transform32*/TransformCounterC__0__to_size_type ) - 8 * sizeof(/*Counter32khz32C.Transform32*/TransformCounterC__0__from_size_type ) + 0, 



  TransformCounterC__0__OVERFLOW_MASK = /*Counter32khz32C.Transform32*/TransformCounterC__0__NUM_UPPER_BITS ? ((/*Counter32khz32C.Transform32*/TransformCounterC__0__upper_count_type )2 << (/*Counter32khz32C.Transform32*/TransformCounterC__0__NUM_UPPER_BITS - 1)) - 1 : 0
};

static /*Counter32khz32C.Transform32*/TransformCounterC__0__to_size_type /*Counter32khz32C.Transform32*/TransformCounterC__0__Counter__get(void );
#line 133
static inline void /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__overflow(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__fired(void );
#line 103
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__size_type t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__size_type dt);
#line 73
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__stop(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Counter__size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Counter__get(void );
# 77 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_t0;
/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_dt;

enum /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0____nesc_unnamed4353 {

  TransformAlarmC__0__MAX_DELAY_LOG2 = 8 * sizeof(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__from_size_type ) - 1 - 0, 
  TransformAlarmC__0__MAX_DELAY = (/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type )1 << /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__MAX_DELAY_LOG2
};

static inline /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__getNow(void );
#line 102
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__stop(void );




static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__set_alarm(void );
#line 147
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type dt);









static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__start(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type dt);




static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__fired(void );
#line 177
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Counter__overflow(void );
# 22 "/home/wtiberti/WSN/tinyos/tos/system/NoInitC.nc"
static inline error_t NoInitC__Init__init(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
static void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__captured(uint16_t time);
# 88 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Capture.nc"
static void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__setEdge(bool up);
#line 64
static void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__reset(void );


static void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__start(void );


static void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__stop(void );
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128GpioCaptureC.nc"
static error_t /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__enableCapture(uint8_t mode);









static inline error_t /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__captureRisingEdge(void );



static inline error_t /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__captureFallingEdge(void );



static inline void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__disable(void );



static inline void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__captured(uint16_t time);
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__clear(void );
#line 51
static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__disable(void );
#line 70
static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__edge(bool low_to_high);
#line 46
static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__enable(void );
# 68 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Interrupt__fired(void );
# 15 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/Atm128GpioInterruptC.nc"
static inline error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__enable(bool rising);
#line 29
static inline error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Interrupt__enableFallingEdge(void );



static inline error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Interrupt__disable(void );




static inline void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
static void HplAtm128InterruptSigP__IntSig6__fired(void );
#line 48
static void HplAtm128InterruptSigP__IntSig1__fired(void );
#line 48
static void HplAtm128InterruptSigP__IntSig4__fired(void );
#line 48
static void HplAtm128InterruptSigP__IntSig7__fired(void );
#line 48
static void HplAtm128InterruptSigP__IntSig2__fired(void );
#line 48
static void HplAtm128InterruptSigP__IntSig5__fired(void );
#line 48
static void HplAtm128InterruptSigP__IntSig0__fired(void );
#line 48
static void HplAtm128InterruptSigP__IntSig3__fired(void );
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSigP.nc"
void __vector_1(void ) __attribute((signal))   ;




void __vector_2(void ) __attribute((signal))   ;




void __vector_3(void ) __attribute((signal))   ;




void __vector_4(void ) __attribute((signal))   ;




void __vector_5(void ) __attribute((signal))   ;




void __vector_6(void ) __attribute((signal))   ;




void __vector_7(void ) __attribute((signal))   ;




void __vector_8(void ) __attribute((signal))   ;
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin0*/HplAtm128InterruptPinP__0__Irq__fired(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin0*/HplAtm128InterruptPinP__0__IrqSignal__fired(void );

static inline void /*HplAtm128InterruptC.IntPin0*/HplAtm128InterruptPinP__0__Irq__default__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin1*/HplAtm128InterruptPinP__1__Irq__fired(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin1*/HplAtm128InterruptPinP__1__IrqSignal__fired(void );

static inline void /*HplAtm128InterruptC.IntPin1*/HplAtm128InterruptPinP__1__Irq__default__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin2*/HplAtm128InterruptPinP__2__Irq__fired(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin2*/HplAtm128InterruptPinP__2__IrqSignal__fired(void );

static inline void /*HplAtm128InterruptC.IntPin2*/HplAtm128InterruptPinP__2__Irq__default__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin3*/HplAtm128InterruptPinP__3__Irq__fired(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin3*/HplAtm128InterruptPinP__3__IrqSignal__fired(void );

static inline void /*HplAtm128InterruptC.IntPin3*/HplAtm128InterruptPinP__3__Irq__default__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin4*/HplAtm128InterruptPinP__4__Irq__fired(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin4*/HplAtm128InterruptPinP__4__IrqSignal__fired(void );

static inline void /*HplAtm128InterruptC.IntPin4*/HplAtm128InterruptPinP__4__Irq__default__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin5*/HplAtm128InterruptPinP__5__Irq__fired(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin5*/HplAtm128InterruptPinP__5__IrqSignal__fired(void );

static inline void /*HplAtm128InterruptC.IntPin5*/HplAtm128InterruptPinP__5__Irq__default__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__fired(void );
# 50 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static __inline void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__clear(void );
static __inline void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__enable(void );
static __inline void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__disable(void );



static __inline void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__edge(bool low_to_high);
#line 70
static inline void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__IrqSignal__fired(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
static void /*HplAtm128InterruptC.IntPin7*/HplAtm128InterruptPinP__7__Irq__fired(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin7*/HplAtm128InterruptPinP__7__IrqSignal__fired(void );

static inline void /*HplAtm128InterruptC.IntPin7*/HplAtm128InterruptPinP__7__Irq__default__fired(void );
# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static bool HplCC2420InterruptsP__CC_CCA__get(void );
# 68 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
static void HplCC2420InterruptsP__CCA__fired(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t HplCC2420InterruptsP__CCATask__postTask(void );
# 69 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/chips/cc2420/HplCC2420InterruptsP.nc"
enum HplCC2420InterruptsP____nesc_unnamed4354 {
#line 69
  HplCC2420InterruptsP__CCATask = 7U
};
#line 69
typedef int HplCC2420InterruptsP____nesc_sillytask_CCATask[HplCC2420InterruptsP__CCATask];
#line 56
uint8_t HplCC2420InterruptsP__ccaWaitForState;

uint8_t HplCC2420InterruptsP__ccaLastState;

bool HplCC2420InterruptsP__ccaCheckDisabled = FALSE;








static inline void HplCC2420InterruptsP__CCATask__runTask(void );
#line 89
static inline error_t HplCC2420InterruptsP__CCA__enableRisingEdge(void );
#line 105
static inline error_t HplCC2420InterruptsP__CCA__disable(void );
# 76 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
static error_t CC2420SpiP__SpiPacket__send(
#line 65
uint8_t * txBuf, 

uint8_t * rxBuf, 








uint16_t len);
# 91 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
static void CC2420SpiP__Fifo__writeDone(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9baa00, 
# 91 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
uint8_t * data, uint8_t length, error_t error);
#line 71
static void CC2420SpiP__Fifo__readDone(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9baa00, 
# 71 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
uint8_t * data, uint8_t length, error_t error);
# 24 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/ChipSpiResource.nc"
static void CC2420SpiP__ChipSpiResource__releasing(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiByte.nc"
static uint8_t CC2420SpiP__SpiByte__write(uint8_t tx);
# 56 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
static void CC2420SpiP__WorkingState__toIdle(void );




static bool CC2420SpiP__WorkingState__isIdle(void );
#line 45
static error_t CC2420SpiP__WorkingState__requestState(uint8_t reqState);
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420SpiP__SpiResource__release(void );
#line 97
static error_t CC2420SpiP__SpiResource__immediateRequest(void );
#line 88
static error_t CC2420SpiP__SpiResource__request(void );
#line 128
static bool CC2420SpiP__SpiResource__isOwner(void );
#line 102
static void CC2420SpiP__Resource__granted(
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f7cba9bb660);
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t CC2420SpiP__grant__postTask(void );
# 88 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
enum CC2420SpiP____nesc_unnamed4355 {
#line 88
  CC2420SpiP__grant = 8U
};
#line 88
typedef int CC2420SpiP____nesc_sillytask_grant[CC2420SpiP__grant];
#line 63
enum CC2420SpiP____nesc_unnamed4356 {
  CC2420SpiP__RESOURCE_COUNT = 5U, 
  CC2420SpiP__NO_HOLDER = 0xFF
};


enum CC2420SpiP____nesc_unnamed4357 {
  CC2420SpiP__S_IDLE, 
  CC2420SpiP__S_BUSY
};


uint16_t CC2420SpiP__m_addr;


uint8_t CC2420SpiP__m_requests = 0;


uint8_t CC2420SpiP__m_holder = CC2420SpiP__NO_HOLDER;


bool CC2420SpiP__release;


static error_t CC2420SpiP__attemptRelease(void );







static inline void CC2420SpiP__ChipSpiResource__abortRelease(void );






static inline error_t CC2420SpiP__ChipSpiResource__attemptRelease(void );




static error_t CC2420SpiP__Resource__request(uint8_t id);
#line 126
static error_t CC2420SpiP__Resource__immediateRequest(uint8_t id);
#line 149
static error_t CC2420SpiP__Resource__release(uint8_t id);
#line 178
static inline bool CC2420SpiP__Resource__isOwner(uint8_t id);





static inline void CC2420SpiP__SpiResource__granted(void );




static cc2420_status_t CC2420SpiP__Fifo__beginRead(uint8_t addr, uint8_t *data, 
uint8_t len);
#line 209
static inline error_t CC2420SpiP__Fifo__continueRead(uint8_t addr, uint8_t *data, 
uint8_t len);



static inline cc2420_status_t CC2420SpiP__Fifo__write(uint8_t addr, uint8_t *data, 
uint8_t len);
#line 260
static cc2420_status_t CC2420SpiP__Ram__write(uint16_t addr, uint8_t offset, 
uint8_t *data, 
uint8_t len);
#line 287
static inline cc2420_status_t CC2420SpiP__Reg__read(uint8_t addr, uint16_t *data);
#line 305
static cc2420_status_t CC2420SpiP__Reg__write(uint8_t addr, uint16_t data);
#line 318
static cc2420_status_t CC2420SpiP__Strobe__strobe(uint8_t addr);










static void CC2420SpiP__SpiPacket__sendDone(uint8_t *tx_buf, uint8_t *rx_buf, 
uint16_t len, error_t error);








static error_t CC2420SpiP__attemptRelease(void );
#line 358
static inline void CC2420SpiP__grant__runTask(void );








static inline void CC2420SpiP__Resource__default__granted(uint8_t id);


static inline void CC2420SpiP__Fifo__default__readDone(uint8_t addr, uint8_t *rx_buf, uint8_t rx_len, error_t error);


static inline void CC2420SpiP__Fifo__default__writeDone(uint8_t addr, uint8_t *tx_buf, uint8_t tx_len, error_t error);
# 74 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
uint8_t StateImplP__state[4U];

enum StateImplP____nesc_unnamed4358 {
  StateImplP__S_IDLE = 0
};


static inline error_t StateImplP__Init__init(void );
#line 96
static error_t StateImplP__State__requestState(uint8_t id, uint8_t reqState);
#line 111
static inline void StateImplP__State__forceState(uint8_t id, uint8_t reqState);






static inline void StateImplP__State__toIdle(uint8_t id);







static inline bool StateImplP__State__isIdle(uint8_t id);






static bool StateImplP__State__isState(uint8_t id, uint8_t myState);
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t Atm128SpiP__zeroTask__postTask(void );
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
static void Atm128SpiP__SpiPacket__sendDone(
#line 81
uint8_t * txBuf, 
uint8_t * rxBuf, 





uint16_t len, 
error_t error);
# 89 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
static void Atm128SpiP__Spi__sleep(void );
#line 83
static void Atm128SpiP__Spi__initMaster(void );
#line 113
static void Atm128SpiP__Spi__enableInterrupt(bool enabled);
#line 97
static uint8_t Atm128SpiP__Spi__read(void );
#line 141
static void Atm128SpiP__Spi__setMasterDoubleSpeed(bool on);
#line 131
static void Atm128SpiP__Spi__setClock(uint8_t speed);




static bool Atm128SpiP__Spi__isInterruptPending(void );
#line 125
static void Atm128SpiP__Spi__setClockPolarity(bool highWhenIdle);
#line 103
static void Atm128SpiP__Spi__write(uint8_t data);
#line 116
static void Atm128SpiP__Spi__enableSpi(bool busOn);
#line 128
static void Atm128SpiP__Spi__setClockPhase(bool sampleOnTrailing);
# 52 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerState.nc"
static void Atm128SpiP__McuPowerState__update(void );
# 294 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128SpiP.nc"
enum Atm128SpiP____nesc_unnamed4359 {
#line 294
  Atm128SpiP__zeroTask = 9U
};
#line 294
typedef int Atm128SpiP____nesc_sillytask_zeroTask[Atm128SpiP__zeroTask];
#line 103
uint16_t Atm128SpiP__len;
uint8_t * Atm128SpiP__txBuffer;
uint8_t * Atm128SpiP__rxBuffer;
uint16_t Atm128SpiP__pos;

enum Atm128SpiP____nesc_unnamed4360 {
  Atm128SpiP__SPI_IDLE, 
  Atm128SpiP__SPI_BUSY, 
  Atm128SpiP__SPI_ATOMIC_SIZE = 10
};
#line 124
enum Atm128SpiP____nesc_unnamed4361 {
  Atm128SpiP__PLATFORM_MHZ = 8
};


static void Atm128SpiP__startSpi(void );
#line 165
static inline void Atm128SpiP__stopSpi(void );







static uint8_t Atm128SpiP__SpiByte__write(uint8_t tx);
#line 249
static error_t Atm128SpiP__sendNextPart(void );
#line 294
static inline void Atm128SpiP__zeroTask__runTask(void );
#line 328
static error_t Atm128SpiP__SpiPacket__send(uint8_t *writeBuf, 
uint8_t *readBuf, 
uint16_t bufLen);
#line 352
static inline void Atm128SpiP__Spi__dataReady(uint8_t data);
#line 392
static inline void Atm128SpiP__ResourceConfigure__configure(uint8_t id);



static inline void Atm128SpiP__ResourceConfigure__unconfigure(uint8_t id);
# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void HplAtm128SpiP__MISO__makeInput(void );

static void HplAtm128SpiP__SCK__makeOutput(void );
#line 46
static void HplAtm128SpiP__SS__makeOutput(void );
# 52 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerState.nc"
static void HplAtm128SpiP__Mcu__update(void );
# 109 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
static void HplAtm128SpiP__SPI__dataReady(uint8_t data);
# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void HplAtm128SpiP__MOSI__makeOutput(void );
# 96 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
static inline void HplAtm128SpiP__SPI__initMaster(void );
#line 112
static inline void HplAtm128SpiP__SPI__sleep(void );


static inline uint8_t HplAtm128SpiP__SPI__read(void );
static inline void HplAtm128SpiP__SPI__write(uint8_t d);


void __vector_17(void ) __attribute((signal))   ;




static inline bool HplAtm128SpiP__SPI__isInterruptPending(void );







static void HplAtm128SpiP__SPI__enableInterrupt(bool enabled);
#line 147
static void HplAtm128SpiP__SPI__enableSpi(bool enabled);
#line 173
static inline void HplAtm128SpiP__SPI__setMasterBit(bool isMaster);
#line 186
static inline void HplAtm128SpiP__SPI__setClockPolarity(bool highWhenIdle);
#line 200
static inline void HplAtm128SpiP__SPI__setClockPhase(bool sampleOnTrailing);
#line 217
static inline void HplAtm128SpiP__SPI__setClock(uint8_t v);
#line 230
static inline void HplAtm128SpiP__SPI__setMasterDoubleSpeed(bool on);
# 49 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
enum /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1____nesc_unnamed4362 {
#line 49
  FcfsResourceQueueC__1__NO_ENTRY = 0xFF
};
uint8_t /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__resQ[1U];
uint8_t /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qHead = /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__NO_ENTRY;
uint8_t /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qTail = /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__NO_ENTRY;

static inline error_t /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__Init__init(void );




static inline bool /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEmpty(void );



static inline bool /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEnqueued(resource_client_id_t id);



static inline resource_client_id_t /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__dequeue(void );
#line 82
static inline error_t /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__enqueue(resource_client_id_t id);
# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__requested(
# 52 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
uint8_t arg_0x7f7cba82e0d0);
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__immediateRequested(
# 52 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
uint8_t arg_0x7f7cba82e0d0);
# 65 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceConfigure__unconfigure(
# 56 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
uint8_t arg_0x7f7cba82d730);
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceConfigure__configure(
# 56 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
uint8_t arg_0x7f7cba82d730);
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
static error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Queue__enqueue(resource_client_id_t id);
#line 53
static bool /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Queue__isEmpty(void );
#line 70
static resource_client_id_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Queue__dequeue(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__granted(
# 51 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
uint8_t arg_0x7f7cba830df0);
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__grantedTask__postTask(void );
# 68 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
enum /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0____nesc_unnamed4363 {
#line 68
  SimpleArbiterP__0__grantedTask = 10U
};
#line 68
typedef int /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0____nesc_sillytask_grantedTask[/*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__grantedTask];
#line 62
enum /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0____nesc_unnamed4364 {
#line 62
  SimpleArbiterP__0__RES_IDLE = 0, SimpleArbiterP__0__RES_GRANTING = 1, SimpleArbiterP__0__RES_BUSY = 2
};
#line 63
enum /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0____nesc_unnamed4365 {
#line 63
  SimpleArbiterP__0__NO_RES = 0xFF
};
uint8_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__state = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__RES_IDLE;
uint8_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__resId = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__NO_RES;



static inline error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__request(uint8_t id);
#line 83
static inline error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__immediateRequest(uint8_t id);
#line 96
static inline error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__release(uint8_t id);
#line 137
static bool /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__isOwner(uint8_t id);






static inline void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__grantedTask__runTask(void );








static inline void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__default__granted(uint8_t id);

static inline void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__default__requested(uint8_t id);

static inline void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__default__immediateRequested(uint8_t id);
# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void HplCC2420SpiP__SS__makeOutput(void );
#line 40
static void HplCC2420SpiP__SS__set(void );
static void HplCC2420SpiP__SS__clr(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void HplCC2420SpiP__Resource__granted(void );
#line 120
static error_t HplCC2420SpiP__SubResource__release(void );
#line 97
static error_t HplCC2420SpiP__SubResource__immediateRequest(void );
#line 88
static error_t HplCC2420SpiP__SubResource__request(void );
#line 128
static bool HplCC2420SpiP__SubResource__isOwner(void );
# 51 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/chips/cc2420/HplCC2420SpiP.nc"
static inline error_t HplCC2420SpiP__Resource__request(void );




static inline error_t HplCC2420SpiP__Resource__immediateRequest(void );










static inline void HplCC2420SpiP__SubResource__granted(void );







static inline error_t HplCC2420SpiP__Resource__release(void );







static inline bool HplCC2420SpiP__Resource__isOwner(void );
# 63 "/home/wtiberti/WSN/tinyos/tos/system/ActiveMessageAddressC.nc"
am_addr_t ActiveMessageAddressC__addr = TOS_AM_ADDRESS;


am_group_t ActiveMessageAddressC__group = TOS_AM_GROUP;






static inline am_addr_t ActiveMessageAddressC__ActiveMessageAddress__amAddress(void );
#line 94
static inline am_group_t ActiveMessageAddressC__ActiveMessageAddress__amGroup(void );
#line 120
static am_addr_t ActiveMessageAddressC__amAddress(void );
# 42 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/LocalIeeeEui64C.nc"
static ieee_eui64_t LocalIeeeEui64C__LocalIeeeEui64__getId(void );
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
static void CC2420TransmitP__RadioBackoff__requestInitialBackoff(message_t * msg);






static void CC2420TransmitP__RadioBackoff__requestCongestionBackoff(message_t * msg);
# 70 "/home/wtiberti/WSN/tinyos/tos/interfaces/PacketTimeStamp.nc"
static void CC2420TransmitP__PacketTimeStamp__clear(
#line 66
message_t * msg);
#line 78
static void CC2420TransmitP__PacketTimeStamp__set(
#line 73
message_t * msg, 




CC2420TransmitP__PacketTimeStamp__size_type value);
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
static cc2420_status_t CC2420TransmitP__STXONCCA__strobe(void );
# 54 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
static error_t CC2420TransmitP__CaptureSFD__captureFallingEdge(void );
#line 66
static void CC2420TransmitP__CaptureSFD__disable(void );
#line 53
static error_t CC2420TransmitP__CaptureSFD__captureRisingEdge(void );
# 109 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static CC2420TransmitP__BackoffTimer__size_type CC2420TransmitP__BackoffTimer__getNow(void );
#line 66
static void CC2420TransmitP__BackoffTimer__start(CC2420TransmitP__BackoffTimer__size_type dt);






static void CC2420TransmitP__BackoffTimer__stop(void );
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Ram.nc"
static cc2420_status_t CC2420TransmitP__TXFIFO_RAM__write(uint8_t offset, uint8_t * data, uint8_t length);
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
static cc2420_status_t CC2420TransmitP__TXCTRL__write(uint16_t data);
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Receive.nc"
static void CC2420TransmitP__CC2420Receive__sfd_dropped(void );
#line 49
static void CC2420TransmitP__CC2420Receive__sfd(uint32_t time);
# 73 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Transmit.nc"
static void CC2420TransmitP__Send__sendDone(message_t * p_msg, error_t error);
# 31 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/ChipSpiResource.nc"
static void CC2420TransmitP__ChipSpiResource__abortRelease(void );







static error_t CC2420TransmitP__ChipSpiResource__attemptRelease(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
static cc2420_status_t CC2420TransmitP__SFLUSHTX__strobe(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void CC2420TransmitP__CSN__makeOutput(void );
#line 40
static void CC2420TransmitP__CSN__set(void );
static void CC2420TransmitP__CSN__clr(void );
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
static cc2420_header_t * CC2420TransmitP__CC2420PacketBody__getHeader(message_t * msg);










static cc2420_metadata_t * CC2420TransmitP__CC2420PacketBody__getMetadata(message_t * msg);
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/PacketTimeSyncOffset.nc"
static uint8_t CC2420TransmitP__PacketTimeSyncOffset__get(
#line 53
message_t * msg);
#line 50
static bool CC2420TransmitP__PacketTimeSyncOffset__isSet(
#line 46
message_t * msg);
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420TransmitP__SpiResource__release(void );
#line 97
static error_t CC2420TransmitP__SpiResource__immediateRequest(void );
#line 88
static error_t CC2420TransmitP__SpiResource__request(void );
# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void CC2420TransmitP__CCA__makeInput(void );
#line 43
static bool CC2420TransmitP__CCA__get(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
static cc2420_status_t CC2420TransmitP__SNOP__strobe(void );
# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void CC2420TransmitP__SFD__makeInput(void );
#line 43
static bool CC2420TransmitP__SFD__get(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
static cc2420_status_t CC2420TransmitP__TXFIFO__write(uint8_t * data, uint8_t length);
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
static cc2420_status_t CC2420TransmitP__STXON__strobe(void );
# 99 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
#line 89
typedef enum CC2420TransmitP____nesc_unnamed4366 {
  CC2420TransmitP__S_STOPPED, 
  CC2420TransmitP__S_STARTED, 
  CC2420TransmitP__S_LOAD, 
  CC2420TransmitP__S_SAMPLE_CCA, 
  CC2420TransmitP__S_BEGIN_TRANSMIT, 
  CC2420TransmitP__S_SFD, 
  CC2420TransmitP__S_EFD, 
  CC2420TransmitP__S_ACK_WAIT, 
  CC2420TransmitP__S_CANCEL
} CC2420TransmitP__cc2420_transmit_state_t;





enum CC2420TransmitP____nesc_unnamed4367 {
  CC2420TransmitP__CC2420_ABORT_PERIOD = 320
};
#line 120
message_t * CC2420TransmitP__m_msg;

bool CC2420TransmitP__m_cca;

uint8_t CC2420TransmitP__m_tx_power;

CC2420TransmitP__cc2420_transmit_state_t CC2420TransmitP__m_state = CC2420TransmitP__S_STOPPED;

bool CC2420TransmitP__m_receiving = FALSE;

uint16_t CC2420TransmitP__m_prev_time;


bool CC2420TransmitP__sfdHigh;


bool CC2420TransmitP__abortSpiRelease;


int8_t CC2420TransmitP__totalCcaChecks;


uint16_t CC2420TransmitP__myInitialBackoff;


uint16_t CC2420TransmitP__myCongestionBackoff;



static inline error_t CC2420TransmitP__send(message_t * p_msg, bool cca);

static void CC2420TransmitP__loadTXFIFO(void );
static void CC2420TransmitP__attemptSend(void );
static void CC2420TransmitP__congestionBackoff(void );
static error_t CC2420TransmitP__acquireSpiResource(void );
static inline error_t CC2420TransmitP__releaseSpiResource(void );
static void CC2420TransmitP__signalDone(error_t err);



static inline error_t CC2420TransmitP__Init__init(void );







static inline error_t CC2420TransmitP__StdControl__start(void );










static inline error_t CC2420TransmitP__StdControl__stop(void );
#line 192
static inline error_t CC2420TransmitP__Send__send(message_t * p_msg, bool useCca);
#line 243
static inline void CC2420TransmitP__RadioBackoff__setInitialBackoff(uint16_t backoffTime);







static inline void CC2420TransmitP__RadioBackoff__setCongestionBackoff(uint16_t backoffTime);







static __inline uint32_t CC2420TransmitP__getTime32(uint16_t captured_time);
#line 280
static inline void CC2420TransmitP__CaptureSFD__captured(uint16_t time);
#line 377
static inline void CC2420TransmitP__ChipSpiResource__releasing(void );
#line 389
static inline void CC2420TransmitP__CC2420Receive__receive(uint8_t type, message_t *ack_msg);
#line 416
static inline void CC2420TransmitP__SpiResource__granted(void );
#line 454
static inline void CC2420TransmitP__TXFIFO__writeDone(uint8_t *tx_buf, uint8_t tx_len, 
error_t error);
#line 486
static inline void CC2420TransmitP__TXFIFO__readDone(uint8_t *tx_buf, uint8_t tx_len, 
error_t error);










static inline void CC2420TransmitP__BackoffTimer__fired(void );
#line 547
static inline error_t CC2420TransmitP__send(message_t * p_msg, bool cca);
#line 743
static void CC2420TransmitP__attemptSend(void );
#line 788
static void CC2420TransmitP__congestionBackoff(void );






static error_t CC2420TransmitP__acquireSpiResource(void );







static inline error_t CC2420TransmitP__releaseSpiResource(void );
#line 825
static void CC2420TransmitP__loadTXFIFO(void );
#line 850
static void CC2420TransmitP__signalDone(error_t err);
# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static bool CC2420ReceiveP__FIFO__get(void );
# 93 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Config.nc"
static bool CC2420ReceiveP__CC2420Config__isAddressRecognitionEnabled(void );
#line 117
static bool CC2420ReceiveP__CC2420Config__isAutoAckEnabled(void );
#line 112
static bool CC2420ReceiveP__CC2420Config__isHwAutoAckDefault(void );
#line 66
static ieee_eui64_t CC2420ReceiveP__CC2420Config__getExtAddr(void );




static uint16_t CC2420ReceiveP__CC2420Config__getShortAddr(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t CC2420ReceiveP__receiveDone_task__postTask(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/interfaces/PacketTimeStamp.nc"
static void CC2420ReceiveP__PacketTimeStamp__clear(
#line 66
message_t * msg);
#line 78
static void CC2420ReceiveP__PacketTimeStamp__set(
#line 73
message_t * msg, 




CC2420ReceiveP__PacketTimeStamp__size_type value);
# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static bool CC2420ReceiveP__FIFOP__get(void );
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Receive.nc"
static void CC2420ReceiveP__CC2420Receive__receive(uint8_t type, message_t * message);
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
static cc2420_status_t CC2420ReceiveP__SACK__strobe(void );
# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void CC2420ReceiveP__CSN__set(void );
static void CC2420ReceiveP__CSN__clr(void );
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
static cc2420_header_t * CC2420ReceiveP__CC2420PacketBody__getHeader(message_t * msg);










static cc2420_metadata_t * CC2420ReceiveP__CC2420PacketBody__getMetadata(message_t * msg);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



CC2420ReceiveP__Receive__receive(
#line 71
message_t * msg, 
void * payload, 





uint8_t len);
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420ReceiveP__SpiResource__release(void );
#line 97
static error_t CC2420ReceiveP__SpiResource__immediateRequest(void );
#line 88
static error_t CC2420ReceiveP__SpiResource__request(void );
#line 128
static bool CC2420ReceiveP__SpiResource__isOwner(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
static error_t CC2420ReceiveP__RXFIFO__continueRead(uint8_t * data, uint8_t length);
#line 51
static cc2420_status_t CC2420ReceiveP__RXFIFO__beginRead(uint8_t * data, uint8_t length);
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
static error_t CC2420ReceiveP__InterruptFIFOP__disable(void );
#line 54
static error_t CC2420ReceiveP__InterruptFIFOP__enableFallingEdge(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
static cc2420_status_t CC2420ReceiveP__SFLUSHRX__strobe(void );
# 148 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
enum CC2420ReceiveP____nesc_unnamed4368 {
#line 148
  CC2420ReceiveP__receiveDone_task = 11U
};
#line 148
typedef int CC2420ReceiveP____nesc_sillytask_receiveDone_task[CC2420ReceiveP__receiveDone_task];
#line 89
#line 81
typedef enum CC2420ReceiveP____nesc_unnamed4369 {
  CC2420ReceiveP__S_STOPPED, 
  CC2420ReceiveP__S_STARTED, 
  CC2420ReceiveP__S_RX_LENGTH, 
  CC2420ReceiveP__S_RX_DEC, 
  CC2420ReceiveP__S_RX_DEC_WAIT, 
  CC2420ReceiveP__S_RX_FCF, 
  CC2420ReceiveP__S_RX_PAYLOAD
} CC2420ReceiveP__cc2420_receive_state_t;

enum CC2420ReceiveP____nesc_unnamed4370 {
  CC2420ReceiveP__RXFIFO_SIZE = 128, 
  CC2420ReceiveP__TIMESTAMP_QUEUE_SIZE = 8, 
  CC2420ReceiveP__SACK_HEADER_LENGTH = 7
};

uint32_t CC2420ReceiveP__m_timestamp_queue[CC2420ReceiveP__TIMESTAMP_QUEUE_SIZE];

uint8_t CC2420ReceiveP__m_timestamp_head;

uint8_t CC2420ReceiveP__m_timestamp_size;





uint8_t CC2420ReceiveP__m_missed_packets;



bool CC2420ReceiveP__receivingPacket;


uint8_t CC2420ReceiveP__rxFrameLength;

uint8_t CC2420ReceiveP__m_bytes_left;

message_t * CC2420ReceiveP__m_p_rx_buf;

message_t CC2420ReceiveP__m_rx_buf;
#line 137
CC2420ReceiveP__cc2420_receive_state_t CC2420ReceiveP__m_state;



static void CC2420ReceiveP__reset_state(void );
static void CC2420ReceiveP__beginReceive(void );
static void CC2420ReceiveP__receive(void );
static void CC2420ReceiveP__waitForNextPacket(void );
static void CC2420ReceiveP__flush(void );
static inline bool CC2420ReceiveP__passesAddressCheck(message_t * msg);




static inline error_t CC2420ReceiveP__Init__init(void );





static inline error_t CC2420ReceiveP__StdControl__start(void );
#line 171
static inline error_t CC2420ReceiveP__StdControl__stop(void );
#line 186
static inline void CC2420ReceiveP__CC2420Receive__sfd(uint32_t time);








static inline void CC2420ReceiveP__CC2420Receive__sfd_dropped(void );
#line 212
static inline void CC2420ReceiveP__InterruptFIFOP__fired(void );
#line 513
static inline void CC2420ReceiveP__SpiResource__granted(void );
#line 530
static inline void CC2420ReceiveP__RXFIFO__readDone(uint8_t *rx_buf, uint8_t rx_len, 
error_t error);
#line 668
static inline void CC2420ReceiveP__RXFIFO__writeDone(uint8_t *tx_buf, uint8_t tx_len, error_t error);







static inline void CC2420ReceiveP__receiveDone_task__runTask(void );
#line 709
static inline void CC2420ReceiveP__CC2420Config__syncDone(error_t error);






static void CC2420ReceiveP__beginReceive(void );
#line 733
static void CC2420ReceiveP__flush(void );
#line 759
static void CC2420ReceiveP__receive(void );









static void CC2420ReceiveP__waitForNextPacket(void );
#line 813
static void CC2420ReceiveP__reset_state(void );










static inline bool CC2420ReceiveP__passesAddressCheck(message_t *msg);
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/packet/CC2420PacketP.nc"
static inline int CC2420PacketP__getAddressLength(int type);








static uint8_t * CC2420PacketP__getNetwork(message_t * msg);
#line 119
static inline uint8_t CC2420PacketP__CC2420Packet__getNetwork(message_t * p_msg);








static inline void CC2420PacketP__CC2420Packet__setNetwork(message_t * p_msg, uint8_t networkId);








static inline cc2420_header_t * CC2420PacketP__CC2420PacketBody__getHeader(message_t * msg);
#line 152
static inline cc2420_metadata_t *CC2420PacketP__CC2420PacketBody__getMetadata(message_t *msg);
#line 171
static void CC2420PacketP__PacketTimeStamp32khz__clear(message_t *msg);





static void CC2420PacketP__PacketTimeStamp32khz__set(message_t *msg, uint32_t value);
#line 210
static inline bool CC2420PacketP__PacketTimeSyncOffset__isSet(message_t *msg);








static inline uint8_t CC2420PacketP__PacketTimeSyncOffset__get(message_t *msg);
# 58 "/home/wtiberti/WSN/tinyos/tos/lib/timer/CounterToLocalTimeC.nc"
static inline void /*CC2420PacketC.CounterToLocalTimeC*/CounterToLocalTimeC__1__Counter__overflow(void );
# 52 "/home/wtiberti/WSN/tinyos/tos/system/RandomMlcgC.nc"
uint32_t RandomMlcgC__seed;


static inline error_t RandomMlcgC__Init__init(void );
#line 69
static uint32_t RandomMlcgC__Random__rand32(void );
#line 89
static inline uint16_t RandomMlcgC__Random__rand16(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static error_t UniqueSendP__SubSend__send(
#line 67
message_t * msg, 







uint8_t len);
#line 112
static uint8_t UniqueSendP__SubSend__maxPayloadLength(void );
#line 100
static void UniqueSendP__Send__sendDone(
#line 96
message_t * msg, 



error_t error);
# 52 "/home/wtiberti/WSN/tinyos/tos/interfaces/Random.nc"
static uint16_t UniqueSendP__Random__rand16(void );
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
static cc2420_header_t * UniqueSendP__CC2420PacketBody__getHeader(message_t * msg);
# 56 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
static void UniqueSendP__State__toIdle(void );
#line 45
static error_t UniqueSendP__State__requestState(uint8_t reqState);
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/unique/UniqueSendP.nc"
uint8_t UniqueSendP__localSendId;

enum UniqueSendP____nesc_unnamed4371 {
  UniqueSendP__S_IDLE, 
  UniqueSendP__S_SENDING
};


static inline error_t UniqueSendP__Init__init(void );
#line 75
static inline error_t UniqueSendP__Send__send(message_t *msg, uint8_t len);
#line 95
static inline uint8_t UniqueSendP__Send__maxPayloadLength(void );








static inline void UniqueSendP__SubSend__sendDone(message_t *msg, error_t error);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



UniqueReceiveP__Receive__receive(
#line 71
message_t * msg, 
void * payload, 





uint8_t len);
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
static cc2420_header_t * UniqueReceiveP__CC2420PacketBody__getHeader(message_t * msg);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



UniqueReceiveP__DuplicateReceive__receive(
#line 71
message_t * msg, 
void * payload, 





uint8_t len);
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/unique/UniqueReceiveP.nc"
#line 56
struct UniqueReceiveP____nesc_unnamed4372 {
  uint16_t source;
  uint8_t dsn;
} UniqueReceiveP__receivedMessages[4];

uint8_t UniqueReceiveP__writeIndex = 0;


uint8_t UniqueReceiveP__recycleSourceElement;

enum UniqueReceiveP____nesc_unnamed4373 {
  UniqueReceiveP__INVALID_ELEMENT = 0xFF
};


static inline error_t UniqueReceiveP__Init__init(void );









static inline bool UniqueReceiveP__hasSeen(uint16_t msgSource, uint8_t msgDsn);
static inline void UniqueReceiveP__insert(uint16_t msgSource, uint8_t msgDsn);
static inline uint16_t UniqueReceiveP__getSourceKey(message_t  *msg);


static inline message_t *UniqueReceiveP__SubReceive__receive(message_t *msg, void *payload, 
uint8_t len);
#line 112
static inline bool UniqueReceiveP__hasSeen(uint16_t msgSource, uint8_t msgDsn);
#line 138
static inline void UniqueReceiveP__insert(uint16_t msgSource, uint8_t msgDsn);
#line 165
static inline uint16_t UniqueReceiveP__getSourceKey(message_t * msg);
#line 192
static inline message_t *UniqueReceiveP__DuplicateReceive__default__receive(message_t *msg, void *payload, uint8_t len);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static error_t CC2420TinyosNetworkP__SubSend__send(
#line 67
message_t * msg, 







uint8_t len);
#line 112
static uint8_t CC2420TinyosNetworkP__SubSend__maxPayloadLength(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t CC2420TinyosNetworkP__grantTask__postTask(void );
# 77 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Packet.nc"
static void CC2420TinyosNetworkP__CC2420Packet__setNetwork(message_t * p_msg, uint8_t networkId);
#line 75
static uint8_t CC2420TinyosNetworkP__CC2420Packet__getNetwork(message_t * p_msg);
# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static void CC2420TinyosNetworkP__ActiveSend__sendDone(
#line 96
message_t * msg, 



error_t error);
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
static error_t CC2420TinyosNetworkP__Queue__enqueue(resource_client_id_t id);
#line 53
static bool CC2420TinyosNetworkP__Queue__isEmpty(void );
#line 70
static resource_client_id_t CC2420TinyosNetworkP__Queue__dequeue(void );
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
static cc2420_header_t * CC2420TinyosNetworkP__CC2420PacketBody__getHeader(message_t * msg);










static cc2420_metadata_t * CC2420TinyosNetworkP__CC2420PacketBody__getMetadata(message_t * msg);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



CC2420TinyosNetworkP__BareReceive__receive(
#line 71
message_t * msg, 
void * payload, 





uint8_t len);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420TinyosNetworkP__Resource__granted(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
uint8_t arg_0x7f7cba42a600);
# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static void CC2420TinyosNetworkP__BareSend__sendDone(
#line 96
message_t * msg, 



error_t error);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



CC2420TinyosNetworkP__ActiveReceive__receive(
#line 71
message_t * msg, 
void * payload, 





uint8_t len);
# 184 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
enum CC2420TinyosNetworkP____nesc_unnamed4374 {
#line 184
  CC2420TinyosNetworkP__grantTask = 12U
};
#line 184
typedef int CC2420TinyosNetworkP____nesc_sillytask_grantTask[CC2420TinyosNetworkP__grantTask];
#line 68
enum CC2420TinyosNetworkP____nesc_unnamed4375 {
  CC2420TinyosNetworkP__OWNER_NONE = 0xff, 
  CC2420TinyosNetworkP__TINYOS_N_NETWORKS = 1U
};




#line 73
enum CC2420TinyosNetworkP____nesc_unnamed4376 {
  CC2420TinyosNetworkP__CLIENT_AM, 
  CC2420TinyosNetworkP__CLIENT_BARE
} CC2420TinyosNetworkP__m_busy_client;

uint8_t CC2420TinyosNetworkP__resource_owner = CC2420TinyosNetworkP__OWNER_NONE;
#line 78
uint8_t CC2420TinyosNetworkP__next_owner;

static error_t CC2420TinyosNetworkP__ActiveSend__send(message_t *msg, uint8_t len);









static inline uint8_t CC2420TinyosNetworkP__ActiveSend__maxPayloadLength(void );



static void *CC2420TinyosNetworkP__ActiveSend__getPayload(message_t *msg, uint8_t len);
#line 139
static inline void *CC2420TinyosNetworkP__BareSend__getPayload(message_t *msg, uint8_t len);









static inline void CC2420TinyosNetworkP__SubSend__sendDone(message_t *msg, error_t error);








static inline message_t *CC2420TinyosNetworkP__SubReceive__receive(message_t *msg, void *payload, uint8_t len);
#line 184
static inline void CC2420TinyosNetworkP__grantTask__runTask(void );
#line 203
static inline error_t CC2420TinyosNetworkP__Resource__request(uint8_t id);
#line 219
static inline error_t CC2420TinyosNetworkP__Resource__immediateRequest(uint8_t id);
#line 233
static inline error_t CC2420TinyosNetworkP__Resource__release(uint8_t id);
#line 245
static inline message_t *CC2420TinyosNetworkP__BareReceive__default__receive(message_t *msg, void *payload, uint8_t len);


static inline void CC2420TinyosNetworkP__BareSend__default__sendDone(message_t *msg, error_t error);








static inline void CC2420TinyosNetworkP__Resource__default__granted(uint8_t client);
# 49 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
enum /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0____nesc_unnamed4377 {
#line 49
  FcfsResourceQueueC__0__NO_ENTRY = 0xFF
};
uint8_t /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__resQ[1];
uint8_t /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qHead = /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__NO_ENTRY;
uint8_t /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qTail = /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__NO_ENTRY;

static inline error_t /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__Init__init(void );




static bool /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__isEmpty(void );



static inline bool /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__isEnqueued(resource_client_id_t id);



static inline resource_client_id_t /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__dequeue(void );
#line 82
static inline error_t /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__enqueue(resource_client_id_t id);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static error_t CC2420ActiveMessageP__SubSend__send(
#line 67
message_t * msg, 







uint8_t len);
#line 125
static 
#line 123
void * 

CC2420ActiveMessageP__SubSend__getPayload(
#line 122
message_t * msg, 


uint8_t len);
#line 112
static uint8_t CC2420ActiveMessageP__SubSend__maxPayloadLength(void );
# 77 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Config.nc"
static uint16_t CC2420ActiveMessageP__CC2420Config__getPanAddr(void );
# 95 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
static void CC2420ActiveMessageP__RadioBackoff__requestCca(
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba393700, 
# 95 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
message_t * msg);
#line 81
static void CC2420ActiveMessageP__RadioBackoff__requestInitialBackoff(
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba393700, 
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
message_t * msg);






static void CC2420ActiveMessageP__RadioBackoff__requestCongestionBackoff(
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba393700, 
# 88 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
message_t * msg);
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/SendNotifier.nc"
static void CC2420ActiveMessageP__SendNotifier__aboutToSend(
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba394b30, 
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/SendNotifier.nc"
am_addr_t dest, 
#line 57
message_t * msg);
# 110 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
static void CC2420ActiveMessageP__AMSend__sendDone(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba39bcf0, 
# 103 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
message_t * msg, 






error_t error);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



CC2420ActiveMessageP__Snoop__receive(
# 50 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba397c40, 
# 71 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
message_t * msg, 
void * payload, 





uint8_t len);
# 50 "/home/wtiberti/WSN/tinyos/tos/interfaces/ActiveMessageAddress.nc"
static am_addr_t CC2420ActiveMessageP__ActiveMessageAddress__amAddress(void );
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
static cc2420_header_t * CC2420ActiveMessageP__CC2420PacketBody__getHeader(message_t * msg);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



CC2420ActiveMessageP__Receive__receive(
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f7cba397060, 
# 71 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
message_t * msg, 
void * payload, 





uint8_t len);
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420ActiveMessageP__RadioResource__release(void );
#line 97
static error_t CC2420ActiveMessageP__RadioResource__immediateRequest(void );
#line 88
static error_t CC2420ActiveMessageP__RadioResource__request(void );
# 71 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
uint16_t CC2420ActiveMessageP__pending_length;
message_t * CC2420ActiveMessageP__pending_message = (void *)0;

static void CC2420ActiveMessageP__RadioResource__granted(void );
#line 87
static error_t CC2420ActiveMessageP__AMSend__send(am_id_t id, am_addr_t addr, 
message_t *msg, 
uint8_t len);
#line 135
static inline am_addr_t CC2420ActiveMessageP__AMPacket__address(void );



static am_addr_t CC2420ActiveMessageP__AMPacket__destination(message_t *amsg);









static inline void CC2420ActiveMessageP__AMPacket__setDestination(message_t *amsg, am_addr_t addr);









static inline bool CC2420ActiveMessageP__AMPacket__isForMe(message_t *amsg);




static inline am_id_t CC2420ActiveMessageP__AMPacket__type(message_t *amsg);




static inline void CC2420ActiveMessageP__AMPacket__setType(message_t *amsg, am_id_t type);
#line 194
static inline uint8_t CC2420ActiveMessageP__Packet__payloadLength(message_t *msg);



static inline void CC2420ActiveMessageP__Packet__setPayloadLength(message_t *msg, uint8_t len);



static inline uint8_t CC2420ActiveMessageP__Packet__maxPayloadLength(void );



static inline void *CC2420ActiveMessageP__Packet__getPayload(message_t *msg, uint8_t len);





static inline void CC2420ActiveMessageP__SubSend__sendDone(message_t *msg, error_t result);






static inline message_t *CC2420ActiveMessageP__SubReceive__receive(message_t *msg, void *payload, uint8_t len);
#line 235
static inline void CC2420ActiveMessageP__CC2420Config__syncDone(error_t error);





static inline void CC2420ActiveMessageP__SubBackoff__requestInitialBackoff(message_t *msg);




static inline void CC2420ActiveMessageP__SubBackoff__requestCongestionBackoff(message_t *msg);



static inline void CC2420ActiveMessageP__SubBackoff__requestCca(message_t *msg);
#line 279
static inline message_t *CC2420ActiveMessageP__Receive__default__receive(am_id_t id, message_t *msg, void *payload, uint8_t len);



static inline message_t *CC2420ActiveMessageP__Snoop__default__receive(am_id_t id, message_t *msg, void *payload, uint8_t len);







static inline void CC2420ActiveMessageP__SendNotifier__default__aboutToSend(am_id_t amId, am_addr_t addr, message_t *msg);

static inline void CC2420ActiveMessageP__RadioBackoff__default__requestInitialBackoff(am_id_t id, 
message_t *msg);


static inline void CC2420ActiveMessageP__RadioBackoff__default__requestCongestionBackoff(am_id_t id, 
message_t *msg);


static inline void CC2420ActiveMessageP__RadioBackoff__default__requestCca(am_id_t id, 
message_t *msg);
# 110 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
static void /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMSend__sendDone(
#line 103
message_t * msg, 






error_t error);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static error_t /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__Send__send(
#line 67
message_t * msg, 







uint8_t len);
# 103 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMPacket.nc"
static void /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMPacket__setDestination(
#line 99
message_t * amsg, 



am_addr_t addr);
#line 162
static void /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMPacket__setType(
#line 158
message_t * amsg, 



am_id_t t);
# 53 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueEntryP.nc"
static inline error_t /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMSend__send(am_addr_t dest, 
message_t *msg, 
uint8_t len);









static inline void /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__Send__sendDone(message_t *m, error_t err);
# 80 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
static error_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMSend__send(
# 51 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
am_id_t arg_0x7f7cba2d0510, 
# 80 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
am_addr_t addr, 
#line 71
message_t * msg, 








uint8_t len);
# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__sendDone(
# 47 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
uint8_t arg_0x7f7cba2d3960, 
# 96 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
message_t * msg, 



error_t error);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Packet.nc"
static uint8_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Packet__payloadLength(
#line 74
message_t * msg);
#line 94
static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Packet__setPayloadLength(
#line 90
message_t * msg, 



uint8_t len);
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__errorTask__postTask(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMPacket.nc"
static am_addr_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMPacket__destination(
#line 74
message_t * amsg);
#line 147
static am_id_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMPacket__type(
#line 143
message_t * amsg);
# 140 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
enum /*AMQueueP.AMQueueImplP*/AMQueueImplP__0____nesc_unnamed4378 {
#line 140
  AMQueueImplP__0__CancelTask = 13U
};
#line 140
typedef int /*AMQueueP.AMQueueImplP*/AMQueueImplP__0____nesc_sillytask_CancelTask[/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__CancelTask];
#line 184
enum /*AMQueueP.AMQueueImplP*/AMQueueImplP__0____nesc_unnamed4379 {
#line 184
  AMQueueImplP__0__errorTask = 14U
};
#line 184
typedef int /*AMQueueP.AMQueueImplP*/AMQueueImplP__0____nesc_sillytask_errorTask[/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__errorTask];
#line 60
#line 58
typedef struct /*AMQueueP.AMQueueImplP*/AMQueueImplP__0____nesc_unnamed4380 {
  message_t * msg;
} /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue_entry_t;

uint8_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current = 1;
/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue_entry_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue[1];
uint8_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__cancelMask[1 / 8 + 1];







static inline void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__tryToSend(void );

static inline void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__nextPacket(void );
#line 105
static inline error_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__send(uint8_t clientId, message_t *msg, 
uint8_t len);
#line 140
static inline void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__CancelTask__runTask(void );
#line 178
static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__sendDone(uint8_t last, message_t * msg, error_t err);





static inline void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__errorTask__runTask(void );




static inline void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__tryToSend(void );
#line 204
static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMSend__sendDone(am_id_t id, message_t *msg, error_t err);
#line 230
static inline void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__default__sendDone(uint8_t id, message_t *msg, error_t err);
# 61 "/home/wtiberti/WSN/tinyos/tos/lib/timer/LocalTime.nc"
static uint32_t TAKSM__LocalTime__get(void );
# 16 "../TAKSM.nc"
static inline uint8_t *TAKSM__tc_getY(uint8_t *data);
static inline uint32_t TAKSM__getSeed(void );
static inline void TAKSM__getNonce(uint8_t *out);
static uint8_t TAKSM__galois_mult(uint8_t a, uint8_t b);
static void TAKSM__elementwise_mult(uint8_t *out, uint8_t *c1, uint8_t *c2);
static void TAKSM__vector_mult(uint8_t *out_ss, uint8_t *c1, uint8_t *c2);
static inline void TAKSM__symmetric_encrypt(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k);
static inline void TAKSM__symmetric_decrypt(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k);
static void TAKSM__authentication_tag(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k);


static inline uint32_t TAKSM__getSeed(void );





static inline void TAKSM__getNonce(uint8_t *out);
#line 104
static inline int TAKSM__TAKS__Encrypt_pw(uint8_t *out_ciphertext, 
uint8_t *plaintext, size_t size, 
uint8_t *out_mac, uint8_t *out_kri, uint8_t *src_LKC, 
uint8_t *src_TKC, uint8_t *dst_TKC);
#line 126
static inline int TAKSM__TAKS__Decrypt_pw(uint8_t *out_plaintext, 
uint8_t *ciphertext, size_t size, 
uint8_t *mac, uint8_t *kri, uint8_t *node_LKC);
#line 145
static inline uint8_t *TAKSM__tc_getY(uint8_t *data);

static void TAKSM__TAKS__ComponentFromHexString(uint8_t *data, const char *s);
#line 160
static uint8_t TAKSM__galois_mult(uint8_t a, uint8_t b);
#line 172
static void TAKSM__elementwise_mult(uint8_t *out, uint8_t *c1, uint8_t *c2);







static void TAKSM__vector_mult(uint8_t *out_ss, uint8_t *c1, uint8_t *c2);
#line 193
static inline void TAKSM__symmetric_encrypt(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k);
#line 207
static inline void TAKSM__symmetric_decrypt(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k);
#line 221
static void TAKSM__authentication_tag(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k);
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static void HplAtm128Timer3P__CompareA__fired(void );
# 60 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Capture.nc"
static void HplAtm128Timer3P__Capture__captured(HplAtm128Timer3P__Capture__size_type t);
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
static void HplAtm128Timer3P__CompareB__fired(void );
#line 58
static void HplAtm128Timer3P__CompareC__fired(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static void HplAtm128Timer3P__Timer__overflow(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer3P.nc"
static inline uint16_t HplAtm128Timer3P__Timer__get(void );


static inline void HplAtm128Timer3P__Timer__set(uint16_t t);








static inline void HplAtm128Timer3P__Timer__setScale(uint8_t s);









static inline Atm128TimerCtrlCapture_t HplAtm128Timer3P__TimerCtrl__getCtrlCapture(void );









static inline uint16_t HplAtm128Timer3P__TimerCtrlCapture2int(Atm128TimerCtrlCapture_t x);






static inline void HplAtm128Timer3P__TimerCtrl__setCtrlCapture(Atm128_TCCR3B_t x);
#line 115
static inline Atm128_ETIFR_t HplAtm128Timer3P__TimerCtrl__getInterruptFlag(void );
#line 136
static inline void HplAtm128Timer3P__Timer__start(void );
#line 148
static inline bool HplAtm128Timer3P__Timer__test(void );
#line 191
static inline uint16_t HplAtm128Timer3P__Capture__get(void );





static inline void HplAtm128Timer3P__CompareA__default__fired(void );
void __vector_26(void ) __attribute((interrupt))   ;


static inline void HplAtm128Timer3P__CompareB__default__fired(void );
void __vector_27(void ) __attribute((interrupt))   ;


static inline void HplAtm128Timer3P__CompareC__default__fired(void );
void __vector_28(void ) __attribute((interrupt))   ;


static inline void HplAtm128Timer3P__Capture__default__captured(uint16_t time);
void __vector_25(void ) __attribute((interrupt))   ;



void __vector_29(void ) __attribute((interrupt))   ;
# 104 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static void /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__setScale(uint8_t scale);
#line 67
static void /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__set(/*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__timer_size t);










static void /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__start(void );
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128TimerInitC.nc"
static inline error_t /*InitThreeP.InitThree*/Atm128TimerInitC__1__Init__init(void );








static inline void /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__overflow(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__overflow(void );
# 87 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
static bool /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__test(void );
#line 61
static /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__timer_size /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__get(void );
# 50 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128CounterC.nc"
static inline /*CounterThree16C.NCounter*/Atm128CounterC__1__timer_size /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__get(void );




static inline bool /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__isOverflowPending(void );









static inline void /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__size_type /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__get(void );






static bool /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__isOverflowPending(void );










static void /*CounterMicro32C.Transform32*/TransformCounterC__1__Counter__overflow(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
/*CounterMicro32C.Transform32*/TransformCounterC__1__upper_count_type /*CounterMicro32C.Transform32*/TransformCounterC__1__m_upper;

enum /*CounterMicro32C.Transform32*/TransformCounterC__1____nesc_unnamed4381 {

  TransformCounterC__1__LOW_SHIFT_RIGHT = 0, 
  TransformCounterC__1__HIGH_SHIFT_LEFT = 8 * sizeof(/*CounterMicro32C.Transform32*/TransformCounterC__1__from_size_type ) - /*CounterMicro32C.Transform32*/TransformCounterC__1__LOW_SHIFT_RIGHT, 
  TransformCounterC__1__NUM_UPPER_BITS = 8 * sizeof(/*CounterMicro32C.Transform32*/TransformCounterC__1__to_size_type ) - 8 * sizeof(/*CounterMicro32C.Transform32*/TransformCounterC__1__from_size_type ) + 0, 



  TransformCounterC__1__OVERFLOW_MASK = /*CounterMicro32C.Transform32*/TransformCounterC__1__NUM_UPPER_BITS ? ((/*CounterMicro32C.Transform32*/TransformCounterC__1__upper_count_type )2 << (/*CounterMicro32C.Transform32*/TransformCounterC__1__NUM_UPPER_BITS - 1)) - 1 : 0
};

static inline /*CounterMicro32C.Transform32*/TransformCounterC__1__to_size_type /*CounterMicro32C.Transform32*/TransformCounterC__1__Counter__get(void );
#line 133
static inline void /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__size_type /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__get(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/lib/timer/CounterToLocalTimeC.nc"
static inline uint32_t /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__LocalTime__get(void );




static inline void /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__overflow(void );
# 50 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartByte.nc"
static error_t SerialPrintfP__UartByte__send(uint8_t byte);
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t SerialPrintfP__UartControl__start(void );
# 50 "/home/wtiberti/WSN/tinyos/tos/lib/printf/SerialPrintfP.nc"
static inline error_t SerialPrintfP__Init__init(void );



static inline error_t SerialPrintfP__StdControl__start(void );









int printfflush(void )   ;




static inline int SerialPrintfP__Putchar__putchar(int c);
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUartTxControl__start(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
static void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__receivedByte(uint8_t byte);
#line 99
static void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__receiveDone(
#line 95
uint8_t * buf, 



uint16_t len, error_t error);
#line 57
static void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__sendDone(
#line 53
uint8_t * buf, 



uint16_t len, error_t error);
# 44 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
static bool /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__isTxEmpty(void );
#line 42
static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__enableRxIntr(void );
#line 41
static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__disableTxIntr(void );

static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__disableRxIntr(void );


static void /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__tx(uint8_t data);
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUartRxControl__start(void );
# 66 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/Atm128UartP.nc"
uint16_t /*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_len;
#line 66
uint16_t /*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_len;
uint8_t * /*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_buf;
#line 67
uint8_t * /*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_buf;
uint16_t /*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_pos;
#line 68
uint16_t /*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_pos;
uint16_t /*Atm128Uart0C.UartP*/Atm128UartP__0__m_byte_time;
uint8_t /*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_intr;
uint8_t /*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_intr;

static inline error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__Init__init(void );







static inline error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__StdControl__start(void );
#line 137
static inline void /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__rxDone(uint8_t data);
#line 177
static inline void /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__txDone(void );
#line 192
static inline error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__UartByte__send(uint8_t byte);
#line 235
static inline void /*Atm128Uart0C.UartP*/Atm128UartP__0__Counter__overflow(void );

static inline void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__default__sendDone(uint8_t *buf, uint16_t len, error_t error);
static inline void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__default__receivedByte(uint8_t byte);
static inline void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__default__receiveDone(uint8_t *buf, uint16_t len, error_t error);
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
static void HplAtm128UartP__HplUart0__rxDone(uint8_t data);
#line 47
static void HplAtm128UartP__HplUart0__txDone(void );

static void HplAtm128UartP__HplUart1__rxDone(uint8_t data);
#line 47
static void HplAtm128UartP__HplUart1__txDone(void );
# 60 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128Calibrate.nc"
static uint16_t HplAtm128UartP__Atm128Calibrate__baudrateRegister(uint32_t baudrate);
# 52 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerState.nc"
static void HplAtm128UartP__McuPowerState__update(void );
# 96 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128UartP.nc"
static inline error_t HplAtm128UartP__Uart0Init__init(void );
#line 116
static inline error_t HplAtm128UartP__Uart0TxControl__start(void );
#line 128
static inline error_t HplAtm128UartP__Uart0RxControl__start(void );
#line 146
static inline error_t HplAtm128UartP__HplUart0__disableTxIntr(void );




static inline error_t HplAtm128UartP__HplUart0__enableRxIntr(void );




static inline error_t HplAtm128UartP__HplUart0__disableRxIntr(void );




static inline bool HplAtm128UartP__HplUart0__isTxEmpty(void );
#line 173
static void HplAtm128UartP__HplUart0__tx(uint8_t data);






void __vector_18(void ) __attribute((signal))   ;





void __vector_20(void ) __attribute((interrupt))   ;



static inline error_t HplAtm128UartP__Uart1Init__init(void );
#line 274
void __vector_30(void ) __attribute((signal))   ;




void __vector_32(void ) __attribute((interrupt))   ;





static inline void HplAtm128UartP__HplUart1__default__txDone(void );
static inline void HplAtm128UartP__HplUart1__default__rxDone(uint8_t data);
# 49 "/home/wtiberti/WSN/tinyos/tos/lib/printf/Putchar.nc"
static int PutcharP__Putchar__putchar(int c);
# 98 "/home/wtiberti/WSN/tinyos/tos/lib/printf/PutcharP.nc"
static inline error_t PutcharP__Init__init(void );
#line 110
int uart_putchar(char c, FILE *stream) __attribute((noinline))   ;
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/atm128hardware.h"
static __inline  void __nesc_disable_interrupt()
#line 92
{
   __asm volatile ("cli" :  :  : "memory");}

#line 109
#line 108
__inline   __nesc_atomic_t 
__nesc_atomic_start(void )
{
  __nesc_atomic_t result = * (volatile uint8_t *)(0x3F + 0x20);

#line 112
  __nesc_disable_interrupt();
   __asm volatile ("" :  :  : "memory");
  return result;
}



#line 118
__inline   void 
__nesc_atomic_end(__nesc_atomic_t original_SREG)
{
   __asm volatile ("" :  :  : "memory");
  * (volatile uint8_t *)(0x3F + 0x20) = original_SREG;
}

# 194 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
static inline void SchedulerBasicP__Scheduler__init(void )
#line 194
{
  /* atomic removed: atomic calls only */
#line 195
  {
    memset((void *)SchedulerBasicP__m_next, SchedulerBasicP__NO_TASK, sizeof SchedulerBasicP__m_next);
    SchedulerBasicP__m_head = SchedulerBasicP__NO_TASK;
    SchedulerBasicP__m_tail = SchedulerBasicP__NO_TASK;
  }
}

# 57 "/home/wtiberti/WSN/tinyos/tos/interfaces/Scheduler.nc"
inline static void RealMainP__Scheduler__init(void ){
#line 57
  SchedulerBasicP__Scheduler__init();
#line 57
}
#line 57
# 77 "/home/wtiberti/WSN/tinyos/tos/types/TinyError.h"
static inline  error_t ecombine(error_t r1, error_t r2)
#line 77
{
  return r1 == r2 ? r1 : FAIL;
}

# 90 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline uint16_t HplAtm128Timer1P__TimerCtrlCapture2int(Atm128TimerCtrlCapture_t x)
#line 90
{
#line 90
  union __nesc_unnamed4382 {
#line 90
    Atm128TimerCtrlCapture_t f;
#line 90
    uint16_t t;
  } 
#line 90
  c = { .f = x };

#line 90
  return c.t;
}





static inline void HplAtm128Timer1P__TimerCtrl__setCtrlCapture(Atm128_TCCR1B_t x)
#line 97
{
  * (volatile uint8_t *)(0x2E + 0x20) = HplAtm128Timer1P__TimerCtrlCapture2int(x);
}

#line 80
static inline Atm128TimerCtrlCapture_t HplAtm128Timer1P__TimerCtrl__getCtrlCapture(void )
#line 80
{
  return * (Atm128TimerCtrlCapture_t * )& * (volatile uint8_t *)(0x2E + 0x20);
}

#line 70
static inline void HplAtm128Timer1P__Timer__setScale(uint8_t s)
#line 70
{
  Atm128TimerCtrlCapture_t x = HplAtm128Timer1P__TimerCtrl__getCtrlCapture();

#line 72
  x.bits.cs = s;
  HplAtm128Timer1P__TimerCtrl__setCtrlCapture(x);
}

# 104 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static void /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__setScale(uint8_t scale){
#line 104
  HplAtm128Timer1P__Timer__setScale(scale);
#line 104
}
#line 104
# 140 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline void HplAtm128Timer1P__Timer__start(void )
#line 140
{
#line 140
  * (volatile uint8_t *)(0x37 + 0x20) |= 1 << 2;
}

# 78 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static void /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__start(void ){
#line 78
  HplAtm128Timer1P__Timer__start();
#line 78
}
#line 78
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline void HplAtm128Timer1P__Timer__set(uint16_t t)
#line 61
{
#line 61
  * (volatile uint16_t *)(0x2C + 0x20) = t;
}

# 67 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static void /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__set(/*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__timer_size t){
#line 67
  HplAtm128Timer1P__Timer__set(t);
#line 67
}
#line 67
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128TimerInitC.nc"
static inline error_t /*InitOneP.InitOne*/Atm128TimerInitC__0__Init__init(void )
#line 51
{
  /* atomic removed: atomic calls only */
#line 52
  {
    /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__set(0);
    /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__start();
    /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__setScale(4);
  }
  return SUCCESS;
}

# 88 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer3P.nc"
static inline uint16_t HplAtm128Timer3P__TimerCtrlCapture2int(Atm128TimerCtrlCapture_t x)
#line 88
{
#line 88
  union __nesc_unnamed4383 {
#line 88
    Atm128TimerCtrlCapture_t f;
#line 88
    uint16_t t;
  } 
#line 88
  c = { .f = x };

#line 88
  return c.t;
}





static inline void HplAtm128Timer3P__TimerCtrl__setCtrlCapture(Atm128_TCCR3B_t x)
#line 95
{
  * (volatile uint8_t *)0x8A = HplAtm128Timer3P__TimerCtrlCapture2int(x);
}

#line 78
static inline Atm128TimerCtrlCapture_t HplAtm128Timer3P__TimerCtrl__getCtrlCapture(void )
#line 78
{
  return * (Atm128TimerCtrlCapture_t *)& * (volatile uint8_t *)0x8A;
}

#line 68
static inline void HplAtm128Timer3P__Timer__setScale(uint8_t s)
#line 68
{
  Atm128TimerCtrlCapture_t x = HplAtm128Timer3P__TimerCtrl__getCtrlCapture();

#line 70
  x.bits.cs = s;
  HplAtm128Timer3P__TimerCtrl__setCtrlCapture(x);
}

# 104 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static void /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__setScale(uint8_t scale){
#line 104
  HplAtm128Timer3P__Timer__setScale(scale);
#line 104
}
#line 104
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer3P.nc"
static inline void HplAtm128Timer3P__Timer__start(void )
#line 136
{
#line 136
  * (volatile uint8_t *)0x7D |= 1 << 2;
}

# 78 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static void /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__start(void ){
#line 78
  HplAtm128Timer3P__Timer__start();
#line 78
}
#line 78
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer3P.nc"
static inline void HplAtm128Timer3P__Timer__set(uint16_t t)
#line 59
{
#line 59
  * (volatile uint16_t *)0x88 = t;
}

# 67 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static void /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__set(/*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__timer_size t){
#line 67
  HplAtm128Timer3P__Timer__set(t);
#line 67
}
#line 67
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128TimerInitC.nc"
static inline error_t /*InitThreeP.InitThree*/Atm128TimerInitC__1__Init__init(void )
#line 51
{
  /* atomic removed: atomic calls only */
#line 52
  {
    /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__set(0);
    /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__start();
    /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__setScale(2);
  }
  return SUCCESS;
}

# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
inline static error_t MotePlatformP__SubInit__init(void ){
#line 62
  enum __nesc_unnamed4242 __nesc_result;
#line 62

#line 62
  __nesc_result = /*InitThreeP.InitThree*/Atm128TimerInitC__1__Init__init();
#line 62
  __nesc_result = ecombine(__nesc_result, /*InitOneP.InitOne*/Atm128TimerInitC__0__Init__init());
#line 62

#line 62
  return __nesc_result;
#line 62
}
#line 62
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit4*/HplAtm128GeneralIOPinP__4__IO__clr(void )
#line 56
{
#line 56
  * (volatile uint8_t * )59U &= ~(1 << 4);
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void MotePlatformP__SerialIdPin__clr(void ){
#line 41
  /*HplAtm128GeneralIOC.PortA.Bit4*/HplAtm128GeneralIOPinP__4__IO__clr();
#line 41
}
#line 41
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit4*/HplAtm128GeneralIOPinP__4__IO__makeInput(void )
#line 59
{
#line 59
  * (volatile uint8_t * )58U &= ~(1 << 4);
}

# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void MotePlatformP__SerialIdPin__makeInput(void ){
#line 44
  /*HplAtm128GeneralIOC.PortA.Bit4*/HplAtm128GeneralIOPinP__4__IO__makeInput();
#line 44
}
#line 44
# 49 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/MotePlatformP.nc"
static inline error_t MotePlatformP__PlatformInit__init(void )
#line 49
{

  * (volatile uint8_t *)(0x15 + 0x20) = 0;
  * (volatile uint8_t *)(0x14 + 0x20) = 0xff;


  MotePlatformP__SerialIdPin__makeInput();
  MotePlatformP__SerialIdPin__clr();

  return MotePlatformP__SubInit__init();
}

# 55 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit0*/HplAtm128GeneralIOPinP__0__IO__set(void )
#line 55
{
#line 55
  * (volatile uint8_t * )59U |= 1 << 0;
}

# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led2__set(void ){
#line 40
  /*HplAtm128GeneralIOC.PortA.Bit0*/HplAtm128GeneralIOPinP__0__IO__set();
#line 40
}
#line 40
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit1*/HplAtm128GeneralIOPinP__1__IO__set(void )
#line 55
{
#line 55
  * (volatile uint8_t * )59U |= 1 << 1;
}

# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led1__set(void ){
#line 40
  /*HplAtm128GeneralIOC.PortA.Bit1*/HplAtm128GeneralIOPinP__1__IO__set();
#line 40
}
#line 40
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit2*/HplAtm128GeneralIOPinP__2__IO__set(void )
#line 55
{
#line 55
  * (volatile uint8_t * )59U |= 1 << 2;
}

# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led0__set(void ){
#line 40
  /*HplAtm128GeneralIOC.PortA.Bit2*/HplAtm128GeneralIOPinP__2__IO__set();
#line 40
}
#line 40
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit0*/HplAtm128GeneralIOPinP__0__IO__makeOutput(void )
#line 61
{
#line 61
  * (volatile uint8_t * )58U |= 1 << 0;
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led2__makeOutput(void ){
#line 46
  /*HplAtm128GeneralIOC.PortA.Bit0*/HplAtm128GeneralIOPinP__0__IO__makeOutput();
#line 46
}
#line 46
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit1*/HplAtm128GeneralIOPinP__1__IO__makeOutput(void )
#line 61
{
#line 61
  * (volatile uint8_t * )58U |= 1 << 1;
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led1__makeOutput(void ){
#line 46
  /*HplAtm128GeneralIOC.PortA.Bit1*/HplAtm128GeneralIOPinP__1__IO__makeOutput();
#line 46
}
#line 46
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit2*/HplAtm128GeneralIOPinP__2__IO__makeOutput(void )
#line 61
{
#line 61
  * (volatile uint8_t * )58U |= 1 << 2;
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led0__makeOutput(void ){
#line 46
  /*HplAtm128GeneralIOC.PortA.Bit2*/HplAtm128GeneralIOPinP__2__IO__makeOutput();
#line 46
}
#line 46
# 56 "/home/wtiberti/WSN/tinyos/tos/system/LedsP.nc"
static inline error_t LedsP__Init__init(void )
#line 56
{
  /* atomic removed: atomic calls only */
#line 57
  {
    ;
    LedsP__Led0__makeOutput();
    LedsP__Led1__makeOutput();
    LedsP__Led2__makeOutput();
    LedsP__Led0__set();
    LedsP__Led1__set();
    LedsP__Led2__set();
  }
  return SUCCESS;
}

# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
inline static error_t PlatformP__MoteInit__init(void ){
#line 62
  enum __nesc_unnamed4242 __nesc_result;
#line 62

#line 62
  __nesc_result = LedsP__Init__init();
#line 62
  __nesc_result = ecombine(__nesc_result, MotePlatformP__PlatformInit__init());
#line 62

#line 62
  return __nesc_result;
#line 62
}
#line 62
# 41 "/home/wtiberti/WSN/tinyos/tos/platforms/mica/MeasureClockC.nc"
static inline error_t MeasureClockC__Init__init(void )
#line 41
{
  /* atomic removed: atomic calls only */



  {
    uint8_t now;
#line 47
    uint8_t wraps;
    uint16_t start;


    * (volatile uint8_t *)(0x2E + 0x20) = 1 << 0;
    * (volatile uint8_t *)(0x30 + 0x20) = 1 << 3;
    * (volatile uint8_t *)(0x33 + 0x20) = (1 << 1) | (1 << 0);




    start = * (volatile uint16_t *)(0x2C + 0x20);
    for (wraps = MeasureClockC__MAGIC / 2; wraps; ) 
      {
        uint16_t next = * (volatile uint16_t *)(0x2C + 0x20);

        if (next < start) {
          wraps--;
          }
#line 65
        start = next;
      }


    now = * (volatile uint8_t *)(0x32 + 0x20);
    while (* (volatile uint8_t *)(0x32 + 0x20) == now) ;


    start = * (volatile uint16_t *)(0x2C + 0x20);
    now = * (volatile uint8_t *)(0x32 + 0x20);
    while (* (volatile uint8_t *)(0x32 + 0x20) == now) ;
    MeasureClockC__cycles = * (volatile uint16_t *)(0x2C + 0x20);

    MeasureClockC__cycles = (MeasureClockC__cycles - start + 16) >> 5;


    * (volatile uint8_t *)(0x30 + 0x20) = * (volatile uint8_t *)(0x2E + 0x20) = * (volatile uint8_t *)(0x33 + 0x20) = 0;
    * (volatile uint8_t *)(0x32 + 0x20) = 0;
    * (volatile uint16_t *)(0x2C + 0x20) = 0;
    * (volatile uint8_t *)0x7C = * (volatile uint8_t *)(0x36 + 0x20) = 0xff;
    while (* (volatile uint8_t *)(0x30 + 0x20) & (((1 << 2) | (1 << 1)) | (1 << 0))) 
      ;
  }
  return SUCCESS;
}

# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
inline static error_t PlatformP__MeasureClock__init(void ){
#line 62
  enum __nesc_unnamed4242 __nesc_result;
#line 62

#line 62
  __nesc_result = MeasureClockC__Init__init();
#line 62

#line 62
  return __nesc_result;
#line 62
}
#line 62
# 49 "/home/wtiberti/WSN/tinyos/tos/platforms/mica/PlatformP.nc"
static inline error_t PlatformP__Init__init(void )
#line 49
{
  error_t ok;


  ok = PlatformP__MeasureClock__init();
  ok = ecombine(ok, PlatformP__MoteInit__init());

  return ok;
}

# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
inline static error_t RealMainP__PlatformInit__init(void ){
#line 62
  enum __nesc_unnamed4242 __nesc_result;
#line 62

#line 62
  __nesc_result = PlatformP__Init__init();
#line 62

#line 62
  return __nesc_result;
#line 62
}
#line 62
# 65 "/home/wtiberti/WSN/tinyos/tos/interfaces/Scheduler.nc"
inline static bool RealMainP__Scheduler__runNextTask(void ){
#line 65
  unsigned char __nesc_result;
#line 65

#line 65
  __nesc_result = SchedulerBasicP__Scheduler__runNextTask();
#line 65

#line 65
  return __nesc_result;
#line 65
}
#line 65
# 97 "BlinkToRadioC.nc"
static inline void BlinkToRadioC__AMSend__sendDone(message_t *msg, error_t err)
#line 97
{
  if (&BlinkToRadioC__pkt == msg) {
      BlinkToRadioC__busy = FALSE;
    }
}

# 110 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
inline static void /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMSend__sendDone(message_t * msg, error_t error){
#line 110
  BlinkToRadioC__AMSend__sendDone(msg, error);
#line 110
}
#line 110
# 65 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueEntryP.nc"
static inline void /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__Send__sendDone(message_t *m, error_t err)
#line 65
{
  /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMSend__sendDone(m, err);
}

# 230 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
static inline void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__default__sendDone(uint8_t id, message_t *msg, error_t err)
#line 230
{
}

# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__sendDone(uint8_t arg_0x7f7cba2d3960, message_t * msg, error_t error){
#line 100
  switch (arg_0x7f7cba2d3960) {
#line 100
    case 0U:
#line 100
      /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__Send__sendDone(msg, error);
#line 100
      break;
#line 100
    default:
#line 100
      /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__default__sendDone(arg_0x7f7cba2d3960, msg, error);
#line 100
      break;
#line 100
    }
#line 100
}
#line 100
# 140 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
static inline void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__CancelTask__runTask(void )
#line 140
{
  uint8_t i;
#line 141
  uint8_t j;
#line 141
  uint8_t mask;
#line 141
  uint8_t last;
  message_t *msg;

  for (i = 0; i < 1 / 8 + 1; i++) {
      if (/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__cancelMask[i]) {
          for (mask = 1, j = 0; j < 8; j++) {
              if (/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__cancelMask[i] & mask) {
                  last = i * 8 + j;
                  msg = /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue[last].msg;
                  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue[last].msg = (void *)0;
                  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__cancelMask[i] &= ~mask;
                  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__sendDone(last, msg, ECANCEL);
                }
              mask <<= 1;
            }
        }
    }
}

#line 184
static inline void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__errorTask__runTask(void )
#line 184
{
  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__sendDone(/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current, /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue[/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current].msg, FAIL);
}

# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__errorTask__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__errorTask);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 80 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
inline static error_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMSend__send(am_id_t arg_0x7f7cba2d0510, am_addr_t addr, message_t * msg, uint8_t len){
#line 80
  enum __nesc_unnamed4242 __nesc_result;
#line 80

#line 80
  __nesc_result = CC2420ActiveMessageP__AMSend__send(arg_0x7f7cba2d0510, addr, msg, len);
#line 80

#line 80
  return __nesc_result;
#line 80
}
#line 80
# 292 "/usr/local/lib/ncc/nesc_nx.h"
static __inline  uint8_t __nesc_ntoh_leuint8(const void * source)
#line 292
{
  const uint8_t *base = source;

#line 294
  return base[0];
}

# 137 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/packet/CC2420PacketP.nc"
static inline cc2420_header_t * CC2420PacketP__CC2420PacketBody__getHeader(message_t * msg)
#line 137
{
  return (cc2420_header_t * )((uint8_t *)msg + (unsigned short )& ((message_t *)0)->data - sizeof(cc2420_header_t ));
}

# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
inline static cc2420_header_t * CC2420ActiveMessageP__CC2420PacketBody__getHeader(message_t * msg){
#line 42
  nx_struct cc2420_header *__nesc_result;
#line 42

#line 42
  __nesc_result = CC2420PacketP__CC2420PacketBody__getHeader(msg);
#line 42

#line 42
  return __nesc_result;
#line 42
}
#line 42
# 194 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline uint8_t CC2420ActiveMessageP__Packet__payloadLength(message_t *msg)
#line 194
{
  return __nesc_ntoh_leuint8(CC2420ActiveMessageP__CC2420PacketBody__getHeader(msg)->length.nxdata) - CC2420_SIZE;
}

# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Packet.nc"
inline static uint8_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Packet__payloadLength(message_t * msg){
#line 78
  unsigned char __nesc_result;
#line 78

#line 78
  __nesc_result = CC2420ActiveMessageP__Packet__payloadLength(msg);
#line 78

#line 78
  return __nesc_result;
#line 78
}
#line 78
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMPacket.nc"
inline static am_addr_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMPacket__destination(message_t * amsg){
#line 78
  unsigned short __nesc_result;
#line 78

#line 78
  __nesc_result = CC2420ActiveMessageP__AMPacket__destination(amsg);
#line 78

#line 78
  return __nesc_result;
#line 78
}
#line 78
# 164 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline am_id_t CC2420ActiveMessageP__AMPacket__type(message_t *amsg)
#line 164
{
  cc2420_header_t *header = CC2420ActiveMessageP__CC2420PacketBody__getHeader(amsg);

#line 166
  return __nesc_ntoh_leuint8(header->type.nxdata);
}

# 147 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMPacket.nc"
inline static am_id_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMPacket__type(message_t * amsg){
#line 147
  unsigned char __nesc_result;
#line 147

#line 147
  __nesc_result = CC2420ActiveMessageP__AMPacket__type(amsg);
#line 147

#line 147
  return __nesc_result;
#line 147
}
#line 147
# 74 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
static inline void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__nextPacket(void )
#line 74
{
  uint8_t i;





  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current++;
  if (/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current >= 1) {
    /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current = 0;
    }
#line 84
  for (i = 0; i < 1; i++) {
      if (/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue[/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current].msg == (void *)0 || 
      /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__cancelMask[/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current / 8] & (1 << /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current % 8)) {
          /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current++;
          if (/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current >= 1) {
            /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current = 0;
            }
        }
      else {
#line 91
        break;
        }
    }
#line 93
  if (i >= 1) {
#line 93
    /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current = 1;
    }
}

#line 189
static inline void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__tryToSend(void )
#line 189
{
  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__nextPacket();
  if (/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current < 1) {
      error_t nextErr;
      message_t *nextMsg = /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue[/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current].msg;
      am_id_t nextId = /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMPacket__type(nextMsg);
      am_addr_t nextDest = /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMPacket__destination(nextMsg);
      uint8_t len = /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Packet__payloadLength(nextMsg);

#line 197
      nextErr = /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMSend__send(nextId, nextDest, nextMsg, len);
      if (nextErr != SUCCESS) {
          /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__errorTask__postTask();
        }
    }
}

# 173 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
static inline uint8_t CC2420CsmaP__Send__maxPayloadLength(void )
#line 173
{
  return 80;
}

# 112 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static uint8_t UniqueSendP__SubSend__maxPayloadLength(void ){
#line 112
  unsigned char __nesc_result;
#line 112

#line 112
  __nesc_result = CC2420CsmaP__Send__maxPayloadLength();
#line 112

#line 112
  return __nesc_result;
#line 112
}
#line 112
# 95 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/unique/UniqueSendP.nc"
static inline uint8_t UniqueSendP__Send__maxPayloadLength(void )
#line 95
{
  return UniqueSendP__SubSend__maxPayloadLength();
}

# 112 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static uint8_t CC2420TinyosNetworkP__SubSend__maxPayloadLength(void ){
#line 112
  unsigned char __nesc_result;
#line 112

#line 112
  __nesc_result = UniqueSendP__Send__maxPayloadLength();
#line 112

#line 112
  return __nesc_result;
#line 112
}
#line 112
# 90 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
static inline uint8_t CC2420TinyosNetworkP__ActiveSend__maxPayloadLength(void )
#line 90
{
  return CC2420TinyosNetworkP__SubSend__maxPayloadLength();
}

# 112 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static uint8_t CC2420ActiveMessageP__SubSend__maxPayloadLength(void ){
#line 112
  unsigned char __nesc_result;
#line 112

#line 112
  __nesc_result = CC2420TinyosNetworkP__ActiveSend__maxPayloadLength();
#line 112

#line 112
  return __nesc_result;
#line 112
}
#line 112
# 202 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline uint8_t CC2420ActiveMessageP__Packet__maxPayloadLength(void )
#line 202
{
  return CC2420ActiveMessageP__SubSend__maxPayloadLength();
}

# 310 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline uint16_t CC2420ControlP__CC2420Config__getPanAddr(void )
#line 310
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 311
    {
      unsigned short __nesc_temp = 
#line 311
      CC2420ControlP__m_pan;

      {
#line 311
        __nesc_atomic_end(__nesc_atomic); 
#line 311
        return __nesc_temp;
      }
    }
#line 313
    __nesc_atomic_end(__nesc_atomic); }
}

# 77 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Config.nc"
inline static uint16_t CC2420ActiveMessageP__CC2420Config__getPanAddr(void ){
#line 77
  unsigned short __nesc_result;
#line 77

#line 77
  __nesc_result = CC2420ControlP__CC2420Config__getPanAddr();
#line 77

#line 77
  return __nesc_result;
#line 77
}
#line 77
# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
inline static bool CC2420TinyosNetworkP__Queue__isEmpty(void ){
#line 53
  unsigned char __nesc_result;
#line 53

#line 53
  __nesc_result = /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__isEmpty();
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 219 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
static inline error_t CC2420TinyosNetworkP__Resource__immediateRequest(uint8_t id)
#line 219
{
  if (CC2420TinyosNetworkP__resource_owner == id) {
#line 220
    return EALREADY;
    }
  if (CC2420TinyosNetworkP__TINYOS_N_NETWORKS > 1) {
      if (CC2420TinyosNetworkP__resource_owner == CC2420TinyosNetworkP__OWNER_NONE && CC2420TinyosNetworkP__Queue__isEmpty()) {
          CC2420TinyosNetworkP__resource_owner = id;
          return SUCCESS;
        }
      return FAIL;
    }
  else 
#line 228
    {
      CC2420TinyosNetworkP__resource_owner = id;
      return SUCCESS;
    }
}

# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420ActiveMessageP__RadioResource__immediateRequest(void ){
#line 97
  enum __nesc_unnamed4242 __nesc_result;
#line 97

#line 97
  __nesc_result = CC2420TinyosNetworkP__Resource__immediateRequest(CC2420ActiveMessageC__CC2420_AM_SEND_ID);
#line 97

#line 97
  return __nesc_result;
#line 97
}
#line 97
# 291 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void CC2420ActiveMessageP__SendNotifier__default__aboutToSend(am_id_t amId, am_addr_t addr, message_t *msg)
#line 291
{
}

# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/SendNotifier.nc"
inline static void CC2420ActiveMessageP__SendNotifier__aboutToSend(am_id_t arg_0x7f7cba394b30, am_addr_t dest, message_t * msg){
#line 59
    CC2420ActiveMessageP__SendNotifier__default__aboutToSend(arg_0x7f7cba394b30, dest, msg);
#line 59
}
#line 59
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static error_t CC2420ActiveMessageP__SubSend__send(message_t * msg, uint8_t len){
#line 75
  enum __nesc_unnamed4242 __nesc_result;
#line 75

#line 75
  __nesc_result = CC2420TinyosNetworkP__ActiveSend__send(msg, len);
#line 75

#line 75
  return __nesc_result;
#line 75
}
#line 75
# 128 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/packet/CC2420PacketP.nc"
static inline void CC2420PacketP__CC2420Packet__setNetwork(message_t * p_msg, uint8_t networkId)
#line 128
{

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    *CC2420PacketP__getNetwork(p_msg) = networkId;
#line 131
    __nesc_atomic_end(__nesc_atomic); }
}

# 77 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Packet.nc"
inline static void CC2420TinyosNetworkP__CC2420Packet__setNetwork(message_t * p_msg, uint8_t networkId){
#line 77
  CC2420PacketP__CC2420Packet__setNetwork(p_msg, networkId);
#line 77
}
#line 77
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/packet/CC2420PacketP.nc"
static inline int CC2420PacketP__getAddressLength(int type)
#line 81
{
  switch (type) {
      case IEEE154_ADDR_SHORT: return 2;
      case IEEE154_ADDR_EXT: return 8;
      case IEEE154_ADDR_NONE: return 0;
      default: return -100;
    }
}

# 297 "/usr/local/lib/ncc/nesc_nx.h"
static __inline  uint8_t __nesc_hton_leuint8(void * target, uint8_t value)
#line 297
{
  uint8_t *base = target;

#line 299
  base[0] = value;
  return value;
}

#line 347
static __inline  uint32_t __nesc_hton_uint32(void * target, uint32_t value)
#line 347
{
  uint8_t *base = target;

#line 349
  base[3] = value;
  base[2] = value >> 8;
  base[1] = value >> 16;
  base[0] = value >> 24;
  return value;
}

#line 286
static __inline  uint8_t __nesc_hton_uint8(void * target, uint8_t value)
#line 286
{
  uint8_t *base = target;

#line 288
  base[0] = value;
  return value;
}

#line 303
static __inline  int8_t __nesc_hton_int8(void * target, int8_t value)
#line 303
{
#line 303
  __nesc_hton_uint8(target, value);
#line 303
  return value;
}

#line 327
static __inline  uint16_t __nesc_hton_leuint16(void * target, uint16_t value)
#line 327
{
  uint8_t *base = target;

#line 329
  base[0] = value;
  base[1] = value >> 8;
  return value;
}

#line 322
static __inline  uint16_t __nesc_ntoh_leuint16(const void * source)
#line 322
{
  const uint8_t *base = source;

#line 324
  return ((uint16_t )base[1] << 8) | base[0];
}

# 547 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline error_t CC2420TransmitP__send(message_t * p_msg, bool cca)
#line 547
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 548
    {
      if (CC2420TransmitP__m_state == CC2420TransmitP__S_CANCEL) {
          {
            enum __nesc_unnamed4242 __nesc_temp = 
#line 550
            ECANCEL;

            {
#line 550
              __nesc_atomic_end(__nesc_atomic); 
#line 550
              return __nesc_temp;
            }
          }
        }
#line 553
      if (CC2420TransmitP__m_state != CC2420TransmitP__S_STARTED) {
          {
            enum __nesc_unnamed4242 __nesc_temp = 
#line 554
            FAIL;

            {
#line 554
              __nesc_atomic_end(__nesc_atomic); 
#line 554
              return __nesc_temp;
            }
          }
        }


      CC2420TransmitP__m_state = CC2420TransmitP__S_LOAD;
      CC2420TransmitP__m_cca = cca;
      CC2420TransmitP__m_msg = p_msg;
      CC2420TransmitP__totalCcaChecks = 0;
    }
#line 564
    __nesc_atomic_end(__nesc_atomic); }

  if (CC2420TransmitP__acquireSpiResource() == SUCCESS) {
      CC2420TransmitP__loadTXFIFO();
    }

  return SUCCESS;
}

#line 192
static inline error_t CC2420TransmitP__Send__send(message_t * p_msg, bool useCca)
#line 192
{
  return CC2420TransmitP__send(p_msg, useCca);
}

# 51 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Transmit.nc"
inline static error_t CC2420CsmaP__CC2420Transmit__send(message_t * p_msg, bool useCca){
#line 51
  enum __nesc_unnamed4242 __nesc_result;
#line 51

#line 51
  __nesc_result = CC2420TransmitP__Send__send(p_msg, useCca);
#line 51

#line 51
  return __nesc_result;
#line 51
}
#line 51
# 301 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void CC2420ActiveMessageP__RadioBackoff__default__requestCca(am_id_t id, 
message_t *msg)
#line 302
{
}

# 95 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
inline static void CC2420ActiveMessageP__RadioBackoff__requestCca(am_id_t arg_0x7f7cba393700, message_t * msg){
#line 95
    CC2420ActiveMessageP__RadioBackoff__default__requestCca(arg_0x7f7cba393700, msg);
#line 95
}
#line 95
# 250 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void CC2420ActiveMessageP__SubBackoff__requestCca(message_t *msg)
#line 250
{

  CC2420ActiveMessageP__RadioBackoff__requestCca(__nesc_ntoh_leuint8(((cc2420_header_t * )((uint8_t *)msg + (unsigned short )& ((message_t *)0)->data - sizeof(cc2420_header_t )))->type.nxdata), msg);
}

# 95 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
inline static void CC2420CsmaP__RadioBackoff__requestCca(message_t * msg){
#line 95
  CC2420ActiveMessageP__SubBackoff__requestCca(msg);
#line 95
}
#line 95
# 111 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
static inline void StateImplP__State__forceState(uint8_t id, uint8_t reqState)
#line 111
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 112
    StateImplP__state[id] = reqState;
#line 112
    __nesc_atomic_end(__nesc_atomic); }
}

# 51 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
inline static void CC2420CsmaP__SplitControlState__forceState(uint8_t reqState){
#line 51
  StateImplP__State__forceState(1U, reqState);
#line 51
}
#line 51
#line 66
inline static bool CC2420CsmaP__SplitControlState__isState(uint8_t myState){
#line 66
  unsigned char __nesc_result;
#line 66

#line 66
  __nesc_result = StateImplP__State__isState(1U, myState);
#line 66

#line 66
  return __nesc_result;
#line 66
}
#line 66
# 152 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/packet/CC2420PacketP.nc"
static inline cc2420_metadata_t *CC2420PacketP__CC2420PacketBody__getMetadata(message_t *msg)
#line 152
{
  return & ((message_metadata_t *)& msg->metadata)->cc2420_meta;
}

# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
inline static cc2420_metadata_t * CC2420CsmaP__CC2420PacketBody__getMetadata(message_t * msg){
#line 53
  nx_struct cc2420_metadata *__nesc_result;
#line 53

#line 53
  __nesc_result = CC2420PacketP__CC2420PacketBody__getMetadata(msg);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
#line 42
inline static cc2420_header_t * CC2420CsmaP__CC2420PacketBody__getHeader(message_t * msg){
#line 42
  nx_struct cc2420_header *__nesc_result;
#line 42

#line 42
  __nesc_result = CC2420PacketP__CC2420PacketBody__getHeader(msg);
#line 42

#line 42
  return __nesc_result;
#line 42
}
#line 42
# 122 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
static inline error_t CC2420CsmaP__Send__send(message_t *p_msg, uint8_t len)
#line 122
{
  unsigned char *__nesc_temp43;
  unsigned char *__nesc_temp42;
#line 124
  cc2420_header_t *header = CC2420CsmaP__CC2420PacketBody__getHeader(p_msg);
  cc2420_metadata_t *metadata = CC2420CsmaP__CC2420PacketBody__getMetadata(p_msg);

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 127
    {
      if (!CC2420CsmaP__SplitControlState__isState(CC2420CsmaP__S_STARTED)) {
          {
            enum __nesc_unnamed4242 __nesc_temp = 
#line 129
            FAIL;

            {
#line 129
              __nesc_atomic_end(__nesc_atomic); 
#line 129
              return __nesc_temp;
            }
          }
        }
#line 132
      CC2420CsmaP__SplitControlState__forceState(CC2420CsmaP__S_TRANSMITTING);
      CC2420CsmaP__m_msg = p_msg;
    }
#line 134
    __nesc_atomic_end(__nesc_atomic); }








  (__nesc_temp42 = header->fcf.nxdata, __nesc_hton_leuint16(__nesc_temp42, __nesc_ntoh_leuint16(__nesc_temp42) & (((1 << IEEE154_FCF_ACK_REQ) | (
  0x3 << IEEE154_FCF_SRC_ADDR_MODE)) | (
  0x3 << IEEE154_FCF_DEST_ADDR_MODE))));

  (__nesc_temp43 = header->fcf.nxdata, __nesc_hton_leuint16(__nesc_temp43, __nesc_ntoh_leuint16(__nesc_temp43) | ((IEEE154_TYPE_DATA << IEEE154_FCF_FRAME_TYPE) | (
  1 << IEEE154_FCF_INTRAPAN))));

  __nesc_hton_int8(metadata->ack.nxdata, FALSE);
  __nesc_hton_uint8(metadata->rssi.nxdata, 0);
  __nesc_hton_uint8(metadata->lqi.nxdata, 0);

  __nesc_hton_uint32(metadata->timestamp.nxdata, CC2420_INVALID_TIMESTAMP);

  CC2420CsmaP__ccaOn = TRUE;
  CC2420CsmaP__RadioBackoff__requestCca(CC2420CsmaP__m_msg);

  CC2420CsmaP__CC2420Transmit__send(CC2420CsmaP__m_msg, CC2420CsmaP__ccaOn);
  return SUCCESS;
}

# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static error_t UniqueSendP__SubSend__send(message_t * msg, uint8_t len){
#line 75
  enum __nesc_unnamed4242 __nesc_result;
#line 75

#line 75
  __nesc_result = CC2420CsmaP__Send__send(msg, len);
#line 75

#line 75
  return __nesc_result;
#line 75
}
#line 75
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
inline static cc2420_header_t * UniqueSendP__CC2420PacketBody__getHeader(message_t * msg){
#line 42
  nx_struct cc2420_header *__nesc_result;
#line 42

#line 42
  __nesc_result = CC2420PacketP__CC2420PacketBody__getHeader(msg);
#line 42

#line 42
  return __nesc_result;
#line 42
}
#line 42
# 45 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
inline static error_t UniqueSendP__State__requestState(uint8_t reqState){
#line 45
  enum __nesc_unnamed4242 __nesc_result;
#line 45

#line 45
  __nesc_result = StateImplP__State__requestState(2U, reqState);
#line 45

#line 45
  return __nesc_result;
#line 45
}
#line 45
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/unique/UniqueSendP.nc"
static inline error_t UniqueSendP__Send__send(message_t *msg, uint8_t len)
#line 75
{
  error_t error;

#line 77
  if (UniqueSendP__State__requestState(UniqueSendP__S_SENDING) == SUCCESS) {
      __nesc_hton_leuint8(UniqueSendP__CC2420PacketBody__getHeader(msg)->dsn.nxdata, UniqueSendP__localSendId++);

      if ((error = UniqueSendP__SubSend__send(msg, len)) != SUCCESS) {
          UniqueSendP__State__toIdle();
        }

      return error;
    }

  return EBUSY;
}

# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static error_t CC2420TinyosNetworkP__SubSend__send(message_t * msg, uint8_t len){
#line 75
  enum __nesc_unnamed4242 __nesc_result;
#line 75

#line 75
  __nesc_result = UniqueSendP__Send__send(msg, len);
#line 75

#line 75
  return __nesc_result;
#line 75
}
#line 75
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420TransmitP__SpiResource__immediateRequest(void ){
#line 97
  enum __nesc_unnamed4242 __nesc_result;
#line 97

#line 97
  __nesc_result = CC2420SpiP__Resource__immediateRequest(/*CC2420TransmitC.Spi*/CC2420SpiC__3__CLIENT_ID);
#line 97

#line 97
  return __nesc_result;
#line 97
}
#line 97
# 45 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
inline static error_t CC2420SpiP__WorkingState__requestState(uint8_t reqState){
#line 45
  enum __nesc_unnamed4242 __nesc_result;
#line 45

#line 45
  __nesc_result = StateImplP__State__requestState(0U, reqState);
#line 45

#line 45
  return __nesc_result;
#line 45
}
#line 45
# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static bool HplCC2420SpiP__SubResource__isOwner(void ){
#line 128
  unsigned char __nesc_result;
#line 128

#line 128
  __nesc_result = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__isOwner(0U);
#line 128

#line 128
  return __nesc_result;
#line 128
}
#line 128
# 83 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/chips/cc2420/HplCC2420SpiP.nc"
static inline bool HplCC2420SpiP__Resource__isOwner(void )
{
  return HplCC2420SpiP__SubResource__isOwner();
}

# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static bool CC2420SpiP__SpiResource__isOwner(void ){
#line 128
  unsigned char __nesc_result;
#line 128

#line 128
  __nesc_result = HplCC2420SpiP__Resource__isOwner();
#line 128

#line 128
  return __nesc_result;
#line 128
}
#line 128
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__clr(void )
#line 56
{
#line 56
  * (volatile uint8_t * )56U &= ~(1 << 0);
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void HplCC2420SpiP__SS__clr(void ){
#line 41
  /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__clr();
#line 41
}
#line 41
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__makeOutput(void )
#line 61
{
#line 61
  * (volatile uint8_t * )55U |= 1 << 0;
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void HplCC2420SpiP__SS__makeOutput(void ){
#line 46
  /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__makeOutput();
#line 46
}
#line 46
# 392 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128SpiP.nc"
static inline void Atm128SpiP__ResourceConfigure__configure(uint8_t id)
#line 392
{
  Atm128SpiP__startSpi();
}

# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
inline static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceConfigure__configure(uint8_t arg_0x7f7cba82d730){
#line 59
  Atm128SpiP__ResourceConfigure__configure(arg_0x7f7cba82d730);
#line 59
}
#line 59
# 157 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
static inline void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__default__immediateRequested(uint8_t id)
#line 157
{
}

# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
inline static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__immediateRequested(uint8_t arg_0x7f7cba82e0d0){
#line 61
    /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__default__immediateRequested(arg_0x7f7cba82e0d0);
#line 61
}
#line 61
# 83 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
static inline error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__immediateRequest(uint8_t id)
#line 83
{
  /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__immediateRequested(/*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__resId);
  /* atomic removed: atomic calls only */
#line 85
  {
    if (/*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__state == /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__RES_IDLE) {
        /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__state = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__RES_BUSY;
        /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__resId = id;
        /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceConfigure__configure(/*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__resId);
        {
          enum __nesc_unnamed4242 __nesc_temp = 
#line 90
          SUCCESS;

#line 90
          return __nesc_temp;
        }
      }
#line 92
    {
      enum __nesc_unnamed4242 __nesc_temp = 
#line 92
      FAIL;

#line 92
      return __nesc_temp;
    }
  }
}

# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t HplCC2420SpiP__SubResource__immediateRequest(void ){
#line 97
  enum __nesc_unnamed4242 __nesc_result;
#line 97

#line 97
  __nesc_result = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__immediateRequest(0U);
#line 97

#line 97
  return __nesc_result;
#line 97
}
#line 97
# 56 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/chips/cc2420/HplCC2420SpiP.nc"
static inline error_t HplCC2420SpiP__Resource__immediateRequest(void )
{
  error_t error = HplCC2420SpiP__SubResource__immediateRequest();

#line 59
  if (error == SUCCESS) 
    {
      HplCC2420SpiP__SS__makeOutput();
      HplCC2420SpiP__SS__clr();
    }
  return error;
}

# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420SpiP__SpiResource__immediateRequest(void ){
#line 97
  enum __nesc_unnamed4242 __nesc_result;
#line 97

#line 97
  __nesc_result = HplCC2420SpiP__Resource__immediateRequest();
#line 97

#line 97
  return __nesc_result;
#line 97
}
#line 97
# 120 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/McuSleepC.nc"
static inline void McuSleepC__McuPowerState__update(void )
#line 120
{
}

# 52 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerState.nc"
inline static void HplAtm128SpiP__Mcu__update(void ){
#line 52
  McuSleepC__McuPowerState__update();
#line 52
}
#line 52
# 173 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
static inline void HplAtm128SpiP__SPI__setMasterBit(bool isMaster)
#line 173
{
  if (isMaster) {
      * (volatile uint8_t *)(0x0D + 0x20) |= 1 << 4;
    }
  else {
      * (volatile uint8_t *)(0x0D + 0x20) &= ~(1 << 4);
    }
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void HplAtm128SpiP__SS__makeOutput(void ){
#line 46
  /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__makeOutput();
#line 46
}
#line 46
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortB.Bit1*/HplAtm128GeneralIOPinP__9__IO__makeOutput(void )
#line 61
{
#line 61
  * (volatile uint8_t * )55U |= 1 << 1;
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void HplAtm128SpiP__SCK__makeOutput(void ){
#line 46
  /*HplAtm128GeneralIOC.PortB.Bit1*/HplAtm128GeneralIOPinP__9__IO__makeOutput();
#line 46
}
#line 46
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortB.Bit3*/HplAtm128GeneralIOPinP__11__IO__makeInput(void )
#line 59
{
#line 59
  * (volatile uint8_t * )55U &= ~(1 << 3);
}

# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void HplAtm128SpiP__MISO__makeInput(void ){
#line 44
  /*HplAtm128GeneralIOC.PortB.Bit3*/HplAtm128GeneralIOPinP__11__IO__makeInput();
#line 44
}
#line 44
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortB.Bit2*/HplAtm128GeneralIOPinP__10__IO__makeOutput(void )
#line 61
{
#line 61
  * (volatile uint8_t * )55U |= 1 << 2;
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void HplAtm128SpiP__MOSI__makeOutput(void ){
#line 46
  /*HplAtm128GeneralIOC.PortB.Bit2*/HplAtm128GeneralIOPinP__10__IO__makeOutput();
#line 46
}
#line 46
# 96 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
static inline void HplAtm128SpiP__SPI__initMaster(void )
#line 96
{
  HplAtm128SpiP__MOSI__makeOutput();
  HplAtm128SpiP__MISO__makeInput();
  HplAtm128SpiP__SCK__makeOutput();
  HplAtm128SpiP__SS__makeOutput();
  HplAtm128SpiP__SPI__setMasterBit(TRUE);
}

# 83 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
inline static void Atm128SpiP__Spi__initMaster(void ){
#line 83
  HplAtm128SpiP__SPI__initMaster();
#line 83
}
#line 83
# 186 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
static inline void HplAtm128SpiP__SPI__setClockPolarity(bool highWhenIdle)
#line 186
{
  if (highWhenIdle) {
      * (volatile uint8_t *)(0x0D + 0x20) |= 1 << 3;
    }
  else {
      * (volatile uint8_t *)(0x0D + 0x20) &= ~(1 << 3);
    }
}

# 125 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
inline static void Atm128SpiP__Spi__setClockPolarity(bool highWhenIdle){
#line 125
  HplAtm128SpiP__SPI__setClockPolarity(highWhenIdle);
#line 125
}
#line 125
# 200 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
static inline void HplAtm128SpiP__SPI__setClockPhase(bool sampleOnTrailing)
#line 200
{
  if (sampleOnTrailing) {
      * (volatile uint8_t *)(0x0D + 0x20) |= 1 << 2;
    }
  else {
      * (volatile uint8_t *)(0x0D + 0x20) &= ~(1 << 2);
    }
}

# 128 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
inline static void Atm128SpiP__Spi__setClockPhase(bool sampleOnTrailing){
#line 128
  HplAtm128SpiP__SPI__setClockPhase(sampleOnTrailing);
#line 128
}
#line 128
# 230 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
static inline void HplAtm128SpiP__SPI__setMasterDoubleSpeed(bool on)
#line 230
{
  if (on) {
      * (volatile uint8_t *)(0x0E + 0x20) |= 1 << 0;
    }
  else {
      * (volatile uint8_t *)(0x0E + 0x20) &= ~(1 << 0);
    }
}

# 141 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
inline static void Atm128SpiP__Spi__setMasterDoubleSpeed(bool on){
#line 141
  HplAtm128SpiP__SPI__setMasterDoubleSpeed(on);
#line 141
}
#line 141
# 217 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
static inline void HplAtm128SpiP__SPI__setClock(uint8_t v)
#line 217
{
  v &= (1 << 1) | (1 << 0);
  * (volatile uint8_t *)(0x0D + 0x20) = (* (volatile uint8_t *)(0x0D + 0x20) & ~((1 << 1) | (1 << 0))) | v;
}

# 131 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
inline static void Atm128SpiP__Spi__setClock(uint8_t speed){
#line 131
  HplAtm128SpiP__SPI__setClock(speed);
#line 131
}
#line 131
# 118 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
static inline void StateImplP__State__toIdle(uint8_t id)
#line 118
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 119
    StateImplP__state[id] = StateImplP__S_IDLE;
#line 119
    __nesc_atomic_end(__nesc_atomic); }
}

# 56 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
inline static void CC2420SpiP__WorkingState__toIdle(void ){
#line 56
  StateImplP__State__toIdle(0U);
#line 56
}
#line 56
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420TransmitP__SpiResource__request(void ){
#line 88
  enum __nesc_unnamed4242 __nesc_result;
#line 88

#line 88
  __nesc_result = CC2420SpiP__Resource__request(/*CC2420TransmitC.Spi*/CC2420SpiC__3__CLIENT_ID);
#line 88

#line 88
  return __nesc_result;
#line 88
}
#line 88
# 175 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
static inline bool SchedulerBasicP__isWaiting(uint8_t id)
#line 175
{
  return SchedulerBasicP__m_next[id] != SchedulerBasicP__NO_TASK || SchedulerBasicP__m_tail == id;
}

static inline bool SchedulerBasicP__pushTask(uint8_t id)
#line 179
{
  if (!SchedulerBasicP__isWaiting(id)) {
      if (SchedulerBasicP__m_head == SchedulerBasicP__NO_TASK) {
          SchedulerBasicP__m_head = id;
          SchedulerBasicP__m_tail = id;
        }
      else 
#line 184
        {
          SchedulerBasicP__m_next[SchedulerBasicP__m_tail] = id;
          SchedulerBasicP__m_tail = id;
        }
      return TRUE;
    }
  else 
#line 189
    {
      return FALSE;
    }
}

#line 148
static inline void SchedulerBasicP__trace_post_task(uint16_t num)
#line 148
{
}

# 64 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
static inline bool /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEnqueued(resource_client_id_t id)
#line 64
{
  /* atomic removed: atomic calls only */
#line 65
  {
    unsigned char __nesc_temp = 
#line 65
    /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__resQ[id] != /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__NO_ENTRY || /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qTail == id;

#line 65
    return __nesc_temp;
  }
}

#line 82
static inline error_t /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__enqueue(resource_client_id_t id)
#line 82
{
  /* atomic removed: atomic calls only */
#line 83
  {
    if (!/*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEnqueued(id)) {
        if (/*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qHead == /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__NO_ENTRY) {
          /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qHead = id;
          }
        else {
#line 88
          /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__resQ[/*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qTail] = id;
          }
#line 89
        /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qTail = id;
        {
          enum __nesc_unnamed4242 __nesc_temp = 
#line 90
          SUCCESS;

#line 90
          return __nesc_temp;
        }
      }
#line 92
    {
      enum __nesc_unnamed4242 __nesc_temp = 
#line 92
      EBUSY;

#line 92
      return __nesc_temp;
    }
  }
}

# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
inline static error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Queue__enqueue(resource_client_id_t id){
#line 79
  enum __nesc_unnamed4242 __nesc_result;
#line 79

#line 79
  __nesc_result = /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__enqueue(id);
#line 79

#line 79
  return __nesc_result;
#line 79
}
#line 79
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__grantedTask__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(/*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__grantedTask);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 155 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
static inline void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__default__requested(uint8_t id)
#line 155
{
}

# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
inline static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__requested(uint8_t arg_0x7f7cba82e0d0){
#line 53
    /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__default__requested(arg_0x7f7cba82e0d0);
#line 53
}
#line 53
# 70 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
static inline error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__request(uint8_t id)
#line 70
{
  /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceRequested__requested(/*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__resId);
  /* atomic removed: atomic calls only */
#line 72
  {
    if (/*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__state == /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__RES_IDLE) {
        /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__state = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__RES_GRANTING;
        /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__resId = id;
        /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__grantedTask__postTask();
        {
          enum __nesc_unnamed4242 __nesc_temp = 
#line 77
          SUCCESS;

#line 77
          return __nesc_temp;
        }
      }
#line 79
    {
      enum __nesc_unnamed4242 __nesc_temp = 
#line 79
      /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Queue__enqueue(id);

#line 79
      return __nesc_temp;
    }
  }
}

# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t HplCC2420SpiP__SubResource__request(void ){
#line 88
  enum __nesc_unnamed4242 __nesc_result;
#line 88

#line 88
  __nesc_result = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__request(0U);
#line 88

#line 88
  return __nesc_result;
#line 88
}
#line 88
# 51 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/chips/cc2420/HplCC2420SpiP.nc"
static inline error_t HplCC2420SpiP__Resource__request(void )
{
  return HplCC2420SpiP__SubResource__request();
}

# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420SpiP__SpiResource__request(void ){
#line 88
  enum __nesc_unnamed4242 __nesc_result;
#line 88

#line 88
  __nesc_result = HplCC2420SpiP__Resource__request();
#line 88

#line 88
  return __nesc_result;
#line 88
}
#line 88
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
inline static cc2420_status_t CC2420TransmitP__TXCTRL__write(uint16_t data){
#line 63
  unsigned char __nesc_result;
#line 63

#line 63
  __nesc_result = CC2420SpiP__Reg__write(CC2420_TXCTRL, data);
#line 63

#line 63
  return __nesc_result;
#line 63
}
#line 63
# 116 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
static inline void HplAtm128SpiP__SPI__write(uint8_t d)
#line 116
{
#line 116
  * (volatile uint8_t *)(0x0F + 0x20) = d;
}

# 103 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
inline static void Atm128SpiP__Spi__write(uint8_t data){
#line 103
  HplAtm128SpiP__SPI__write(data);
#line 103
}
#line 103
# 124 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
static inline bool HplAtm128SpiP__SPI__isInterruptPending(void )
#line 124
{
  return (* (volatile uint8_t *)(0x0E + 0x20) & (1 << 7)) != 0;
}

# 136 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
inline static bool Atm128SpiP__Spi__isInterruptPending(void ){
#line 136
  unsigned char __nesc_result;
#line 136

#line 136
  __nesc_result = HplAtm128SpiP__SPI__isInterruptPending();
#line 136

#line 136
  return __nesc_result;
#line 136
}
#line 136
# 76 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
inline static error_t CC2420SpiP__SpiPacket__send(uint8_t * txBuf, uint8_t * rxBuf, uint16_t len){
#line 76
  enum __nesc_unnamed4242 __nesc_result;
#line 76

#line 76
  __nesc_result = Atm128SpiP__SpiPacket__send(txBuf, rxBuf, len);
#line 76

#line 76
  return __nesc_result;
#line 76
}
#line 76
# 45 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiByte.nc"
inline static uint8_t CC2420SpiP__SpiByte__write(uint8_t tx){
#line 45
  unsigned char __nesc_result;
#line 45

#line 45
  __nesc_result = Atm128SpiP__SpiByte__write(tx);
#line 45

#line 45
  return __nesc_result;
#line 45
}
#line 45
# 126 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
static inline bool StateImplP__State__isIdle(uint8_t id)
#line 126
{
  return StateImplP__State__isState(id, StateImplP__S_IDLE);
}

# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
inline static bool CC2420SpiP__WorkingState__isIdle(void ){
#line 61
  unsigned char __nesc_result;
#line 61

#line 61
  __nesc_result = StateImplP__State__isIdle(0U);
#line 61

#line 61
  return __nesc_result;
#line 61
}
#line 61
# 214 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static inline cc2420_status_t CC2420SpiP__Fifo__write(uint8_t addr, uint8_t *data, 
uint8_t len)
#line 215
{

  uint8_t status = 0;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 219
    {
      if (CC2420SpiP__WorkingState__isIdle()) {
          {
            unsigned char __nesc_temp = 
#line 221
            status;

            {
#line 221
              __nesc_atomic_end(__nesc_atomic); 
#line 221
              return __nesc_temp;
            }
          }
        }
    }
#line 225
    __nesc_atomic_end(__nesc_atomic); }
#line 225
  CC2420SpiP__m_addr = addr;

  status = CC2420SpiP__SpiByte__write(CC2420SpiP__m_addr);
  CC2420SpiP__SpiPacket__send(data, (void *)0, len);

  return status;
}

# 82 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
inline static cc2420_status_t CC2420TransmitP__TXFIFO__write(uint8_t * data, uint8_t length){
#line 82
  unsigned char __nesc_result;
#line 82

#line 82
  __nesc_result = CC2420SpiP__Fifo__write(CC2420_TXFIFO, data, length);
#line 82

#line 82
  return __nesc_result;
#line 82
}
#line 82
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t Atm128SpiP__zeroTask__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(Atm128SpiP__zeroTask);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 64 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
static inline bool /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__isEnqueued(resource_client_id_t id)
#line 64
{
  /* atomic removed: atomic calls only */
#line 65
  {
    unsigned char __nesc_temp = 
#line 65
    /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__resQ[id] != /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__NO_ENTRY || /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qTail == id;

#line 65
    return __nesc_temp;
  }
}

#line 82
static inline error_t /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__enqueue(resource_client_id_t id)
#line 82
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 83
    {
      if (!/*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__isEnqueued(id)) {
          if (/*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qHead == /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__NO_ENTRY) {
            /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qHead = id;
            }
          else {
#line 88
            /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__resQ[/*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qTail] = id;
            }
#line 89
          /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qTail = id;
          {
            enum __nesc_unnamed4242 __nesc_temp = 
#line 90
            SUCCESS;

            {
#line 90
              __nesc_atomic_end(__nesc_atomic); 
#line 90
              return __nesc_temp;
            }
          }
        }
#line 92
      {
        enum __nesc_unnamed4242 __nesc_temp = 
#line 92
        EBUSY;

        {
#line 92
          __nesc_atomic_end(__nesc_atomic); 
#line 92
          return __nesc_temp;
        }
      }
    }
#line 95
    __nesc_atomic_end(__nesc_atomic); }
}

# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
inline static error_t CC2420TinyosNetworkP__Queue__enqueue(resource_client_id_t id){
#line 79
  enum __nesc_unnamed4242 __nesc_result;
#line 79

#line 79
  __nesc_result = /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__enqueue(id);
#line 79

#line 79
  return __nesc_result;
#line 79
}
#line 79
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t CC2420TinyosNetworkP__grantTask__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(CC2420TinyosNetworkP__grantTask);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 203 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
static inline error_t CC2420TinyosNetworkP__Resource__request(uint8_t id)
#line 203
{

  CC2420TinyosNetworkP__grantTask__postTask();

  if (CC2420TinyosNetworkP__TINYOS_N_NETWORKS > 1) {
      return CC2420TinyosNetworkP__Queue__enqueue(id);
    }
  else 
#line 209
    {
      if (id == CC2420TinyosNetworkP__resource_owner) {
          return EALREADY;
        }
      else 
#line 212
        {
          CC2420TinyosNetworkP__next_owner = id;
          return SUCCESS;
        }
    }
}

# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420ActiveMessageP__RadioResource__request(void ){
#line 88
  enum __nesc_unnamed4242 __nesc_result;
#line 88

#line 88
  __nesc_result = CC2420TinyosNetworkP__Resource__request(CC2420ActiveMessageC__CC2420_AM_SEND_ID);
#line 88

#line 88
  return __nesc_result;
#line 88
}
#line 88
# 233 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
static inline error_t CC2420TinyosNetworkP__Resource__release(uint8_t id)
#line 233
{
  if (CC2420TinyosNetworkP__TINYOS_N_NETWORKS > 1) {
      CC2420TinyosNetworkP__grantTask__postTask();
    }
  CC2420TinyosNetworkP__resource_owner = CC2420TinyosNetworkP__OWNER_NONE;
  return SUCCESS;
}

#line 257
static inline void CC2420TinyosNetworkP__Resource__default__granted(uint8_t client)
#line 257
{
  CC2420TinyosNetworkP__Resource__release(client);
}

# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static void CC2420TinyosNetworkP__Resource__granted(uint8_t arg_0x7f7cba42a600){
#line 102
  switch (arg_0x7f7cba42a600) {
#line 102
    case CC2420ActiveMessageC__CC2420_AM_SEND_ID:
#line 102
      CC2420ActiveMessageP__RadioResource__granted();
#line 102
      break;
#line 102
    default:
#line 102
      CC2420TinyosNetworkP__Resource__default__granted(arg_0x7f7cba42a600);
#line 102
      break;
#line 102
    }
#line 102
}
#line 102
# 68 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
static inline resource_client_id_t /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__dequeue(void )
#line 68
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 69
    {
      if (/*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qHead != /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__NO_ENTRY) {
          uint8_t id = /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qHead;

#line 72
          /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qHead = /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__resQ[/*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qHead];
          if (/*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qHead == /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__NO_ENTRY) {
            /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qTail = /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__NO_ENTRY;
            }
#line 75
          /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__resQ[id] = /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__NO_ENTRY;
          {
            unsigned char __nesc_temp = 
#line 76
            id;

            {
#line 76
              __nesc_atomic_end(__nesc_atomic); 
#line 76
              return __nesc_temp;
            }
          }
        }
#line 78
      {
        unsigned char __nesc_temp = 
#line 78
        /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__NO_ENTRY;

        {
#line 78
          __nesc_atomic_end(__nesc_atomic); 
#line 78
          return __nesc_temp;
        }
      }
    }
#line 81
    __nesc_atomic_end(__nesc_atomic); }
}

# 70 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
inline static resource_client_id_t CC2420TinyosNetworkP__Queue__dequeue(void ){
#line 70
  unsigned char __nesc_result;
#line 70

#line 70
  __nesc_result = /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__dequeue();
#line 70

#line 70
  return __nesc_result;
#line 70
}
#line 70
# 184 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
static inline void CC2420TinyosNetworkP__grantTask__runTask(void )
#line 184
{


  if (CC2420TinyosNetworkP__TINYOS_N_NETWORKS > 1) {
      if (CC2420TinyosNetworkP__resource_owner == CC2420TinyosNetworkP__OWNER_NONE && !CC2420TinyosNetworkP__Queue__isEmpty()) {
          CC2420TinyosNetworkP__resource_owner = CC2420TinyosNetworkP__Queue__dequeue();

          if (CC2420TinyosNetworkP__resource_owner != CC2420TinyosNetworkP__OWNER_NONE) {
              CC2420TinyosNetworkP__Resource__granted(CC2420TinyosNetworkP__resource_owner);
            }
        }
    }
  else 
#line 195
    {
      if (CC2420TinyosNetworkP__next_owner != CC2420TinyosNetworkP__resource_owner) {
          CC2420TinyosNetworkP__resource_owner = CC2420TinyosNetworkP__next_owner;
          CC2420TinyosNetworkP__Resource__granted(CC2420TinyosNetworkP__resource_owner);
        }
    }
}

# 281 "/usr/local/lib/ncc/nesc_nx.h"
static __inline  uint8_t __nesc_ntoh_uint8(const void * source)
#line 281
{
  const uint8_t *base = source;

#line 283
  return base[0];
}

#line 303
static __inline  int8_t __nesc_ntoh_int8(const void * source)
#line 303
{
#line 303
  return __nesc_ntoh_uint8(source);
}

# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
inline static cc2420_header_t * CC2420TinyosNetworkP__CC2420PacketBody__getHeader(message_t * msg){
#line 42
  nx_struct cc2420_header *__nesc_result;
#line 42

#line 42
  __nesc_result = CC2420PacketP__CC2420PacketBody__getHeader(msg);
#line 42

#line 42
  return __nesc_result;
#line 42
}
#line 42
# 139 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
static inline void *CC2420TinyosNetworkP__BareSend__getPayload(message_t *msg, uint8_t len)
#line 139
{

  cc2420_header_t *hdr = CC2420TinyosNetworkP__CC2420PacketBody__getHeader(msg);

#line 142
  return hdr;
}

#line 245
static inline message_t *CC2420TinyosNetworkP__BareReceive__default__receive(message_t *msg, void *payload, uint8_t len)
#line 245
{
  return msg;
}

# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
inline static message_t * CC2420TinyosNetworkP__BareReceive__receive(message_t * msg, void * payload, uint8_t len){
#line 78
  nx_struct message_t *__nesc_result;
#line 78

#line 78
  __nesc_result = CC2420TinyosNetworkP__BareReceive__default__receive(msg, payload, len);
#line 78

#line 78
  return __nesc_result;
#line 78
}
#line 78
# 283 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline message_t *CC2420ActiveMessageP__Snoop__default__receive(am_id_t id, message_t *msg, void *payload, uint8_t len)
#line 283
{
  return msg;
}

# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
inline static message_t * CC2420ActiveMessageP__Snoop__receive(am_id_t arg_0x7f7cba397c40, message_t * msg, void * payload, uint8_t len){
#line 78
  nx_struct message_t *__nesc_result;
#line 78

#line 78
    __nesc_result = CC2420ActiveMessageP__Snoop__default__receive(arg_0x7f7cba397c40, msg, payload, len);
#line 78

#line 78
  return __nesc_result;
#line 78
}
#line 78
# 109 "/home/wtiberti/WSN/tinyos/tos/system/LedsP.nc"
static inline void LedsP__Leds__led2Off(void )
#line 109
{
  LedsP__Led2__set();
  ;
#line 111
  ;
}

# 94 "/home/wtiberti/WSN/tinyos/tos/interfaces/Leds.nc"
inline static void BlinkToRadioC__Leds__led2Off(void ){
#line 94
  LedsP__Leds__led2Off();
#line 94
}
#line 94
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit0*/HplAtm128GeneralIOPinP__0__IO__clr(void )
#line 56
{
#line 56
  * (volatile uint8_t * )59U &= ~(1 << 0);
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led2__clr(void ){
#line 41
  /*HplAtm128GeneralIOC.PortA.Bit0*/HplAtm128GeneralIOPinP__0__IO__clr();
#line 41
}
#line 41
# 104 "/home/wtiberti/WSN/tinyos/tos/system/LedsP.nc"
static inline void LedsP__Leds__led2On(void )
#line 104
{
  LedsP__Led2__clr();
  ;
#line 106
  ;
}

# 89 "/home/wtiberti/WSN/tinyos/tos/interfaces/Leds.nc"
inline static void BlinkToRadioC__Leds__led2On(void ){
#line 89
  LedsP__Leds__led2On();
#line 89
}
#line 89
# 94 "/home/wtiberti/WSN/tinyos/tos/system/LedsP.nc"
static inline void LedsP__Leds__led1Off(void )
#line 94
{
  LedsP__Led1__set();
  ;
#line 96
  ;
}

# 77 "/home/wtiberti/WSN/tinyos/tos/interfaces/Leds.nc"
inline static void BlinkToRadioC__Leds__led1Off(void ){
#line 77
  LedsP__Leds__led1Off();
#line 77
}
#line 77
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit1*/HplAtm128GeneralIOPinP__1__IO__clr(void )
#line 56
{
#line 56
  * (volatile uint8_t * )59U &= ~(1 << 1);
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led1__clr(void ){
#line 41
  /*HplAtm128GeneralIOC.PortA.Bit1*/HplAtm128GeneralIOPinP__1__IO__clr();
#line 41
}
#line 41
# 89 "/home/wtiberti/WSN/tinyos/tos/system/LedsP.nc"
static inline void LedsP__Leds__led1On(void )
#line 89
{
  LedsP__Led1__clr();
  ;
#line 91
  ;
}

# 72 "/home/wtiberti/WSN/tinyos/tos/interfaces/Leds.nc"
inline static void BlinkToRadioC__Leds__led1On(void ){
#line 72
  LedsP__Leds__led1On();
#line 72
}
#line 72
# 79 "/home/wtiberti/WSN/tinyos/tos/system/LedsP.nc"
static inline void LedsP__Leds__led0Off(void )
#line 79
{
  LedsP__Led0__set();
  ;
#line 81
  ;
}

# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/Leds.nc"
inline static void BlinkToRadioC__Leds__led0Off(void ){
#line 61
  LedsP__Leds__led0Off();
#line 61
}
#line 61
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit2*/HplAtm128GeneralIOPinP__2__IO__clr(void )
#line 56
{
#line 56
  * (volatile uint8_t * )59U &= ~(1 << 2);
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led0__clr(void ){
#line 41
  /*HplAtm128GeneralIOC.PortA.Bit2*/HplAtm128GeneralIOPinP__2__IO__clr();
#line 41
}
#line 41
# 74 "/home/wtiberti/WSN/tinyos/tos/system/LedsP.nc"
static inline void LedsP__Leds__led0On(void )
#line 74
{
  LedsP__Led0__clr();
  ;
#line 76
  ;
}

# 56 "/home/wtiberti/WSN/tinyos/tos/interfaces/Leds.nc"
inline static void BlinkToRadioC__Leds__led0On(void ){
#line 56
  LedsP__Leds__led0On();
#line 56
}
#line 56
# 26 "BlinkToRadioC.nc"
static inline void BlinkToRadioC__setLeds(uint16_t val)
#line 26
{
  if (val & 0x01) {
    BlinkToRadioC__Leds__led0On();
    }
  else {
#line 30
    BlinkToRadioC__Leds__led0Off();
    }
#line 31
  if (val & 0x02) {
    BlinkToRadioC__Leds__led1On();
    }
  else {
#line 34
    BlinkToRadioC__Leds__led1Off();
    }
#line 35
  if (val & 0x04) {
    BlinkToRadioC__Leds__led2On();
    }
  else {
#line 38
    BlinkToRadioC__Leds__led2Off();
    }
}

# 207 "../TAKSM.nc"
static inline void TAKSM__symmetric_decrypt(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k)
{



  int i;

#line 213
  for (i = 0; i < size; ++i) {
      out[i] = in[i] ^ k[i % 16];
    }
}

#line 126
static inline int TAKSM__TAKS__Decrypt_pw(uint8_t *out_plaintext, 
uint8_t *ciphertext, size_t size, 
uint8_t *mac, uint8_t *kri, uint8_t *node_LKC)
{
  int i;
  uint8_t ss[16];
  uint8_t computed_mac[4];
  size_t minsize;

#line 134
  TAKSM__vector_mult(ss, kri, node_LKC);

  TAKSM__authentication_tag(computed_mac, ciphertext, size, ss);
  for (i = 0; i < 4; ++i) {
      if (computed_mac[i] != mac[i]) {
        return -1;
        }
    }
#line 141
  TAKSM__symmetric_decrypt(out_plaintext, ciphertext, size, ss);
  return 0;
}

# 8 "../TAKS.nc"
inline static int BlinkToRadioC__TAKS__Decrypt_pw(uint8_t *out_plaintext, uint8_t *ciphertext, size_t size, uint8_t *mac, uint8_t *kri, uint8_t *node_LKC){
#line 8
  int __nesc_result;
#line 8

#line 8
  __nesc_result = TAKSM__TAKS__Decrypt_pw(out_plaintext, ciphertext, size, mac, kri, node_LKC);
#line 8

#line 8
  return __nesc_result;
#line 8
}
#line 8
# 103 "BlinkToRadioC.nc"
static inline message_t *BlinkToRadioC__Receive__receive(message_t *msg, void *payload, uint8_t len)
#line 103
{
  BlinkToRadioMsg temp;

#line 105
  if (len == sizeof(BlinkToRadioMsg )) {
      int i;
#line 106
      int r;
      BlinkToRadioMsg *btrpkt = (BlinkToRadioMsg *)payload;

#line 108
      printf("Received: ");
      for (i = 0; i < 16; ++i) {
          printf("%02x ", btrpkt->payload[i]);
        }
      r = BlinkToRadioC__TAKS__Decrypt_pw(temp.payload, btrpkt->payload, 16, btrpkt->mac, btrpkt->kri, BlinkToRadioC__LKC);
      printf(" -> (%d). Decrypted: ", r);
      for (i = 0; i < 16; ++i) {
          printf("%02x ", temp.payload[i]);
        }
      printf("\r\n");
      if (r != -1) {
          BlinkToRadioC__setLeds(temp.payload[0]);
        }
    }
  return msg;
}

# 279 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline message_t *CC2420ActiveMessageP__Receive__default__receive(am_id_t id, message_t *msg, void *payload, uint8_t len)
#line 279
{
  return msg;
}

# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
inline static message_t * CC2420ActiveMessageP__Receive__receive(am_id_t arg_0x7f7cba397060, message_t * msg, void * payload, uint8_t len){
#line 78
  nx_struct message_t *__nesc_result;
#line 78

#line 78
  switch (arg_0x7f7cba397060) {
#line 78
    case 6:
#line 78
      __nesc_result = BlinkToRadioC__Receive__receive(msg, payload, len);
#line 78
      break;
#line 78
    default:
#line 78
      __nesc_result = CC2420ActiveMessageP__Receive__default__receive(arg_0x7f7cba397060, msg, payload, len);
#line 78
      break;
#line 78
    }
#line 78

#line 78
  return __nesc_result;
#line 78
}
#line 78
# 73 "/home/wtiberti/WSN/tinyos/tos/system/ActiveMessageAddressC.nc"
static inline am_addr_t ActiveMessageAddressC__ActiveMessageAddress__amAddress(void )
#line 73
{
  return ActiveMessageAddressC__amAddress();
}

# 50 "/home/wtiberti/WSN/tinyos/tos/interfaces/ActiveMessageAddress.nc"
inline static am_addr_t CC2420ActiveMessageP__ActiveMessageAddress__amAddress(void ){
#line 50
  unsigned short __nesc_result;
#line 50

#line 50
  __nesc_result = ActiveMessageAddressC__ActiveMessageAddress__amAddress();
#line 50

#line 50
  return __nesc_result;
#line 50
}
#line 50
# 135 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline am_addr_t CC2420ActiveMessageP__AMPacket__address(void )
#line 135
{
  return CC2420ActiveMessageP__ActiveMessageAddress__amAddress();
}

#line 159
static inline bool CC2420ActiveMessageP__AMPacket__isForMe(message_t *amsg)
#line 159
{
  return CC2420ActiveMessageP__AMPacket__destination(amsg) == CC2420ActiveMessageP__AMPacket__address() || 
  CC2420ActiveMessageP__AMPacket__destination(amsg) == AM_BROADCAST_ADDR;
}

#line 219
static inline message_t *CC2420ActiveMessageP__SubReceive__receive(message_t *msg, void *payload, uint8_t len)
#line 219
{

  if (CC2420ActiveMessageP__AMPacket__isForMe(msg)) {
      return CC2420ActiveMessageP__Receive__receive(CC2420ActiveMessageP__AMPacket__type(msg), msg, payload, len);
    }
  else {
      return CC2420ActiveMessageP__Snoop__receive(CC2420ActiveMessageP__AMPacket__type(msg), msg, payload, len);
    }
}

# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
inline static message_t * CC2420TinyosNetworkP__ActiveReceive__receive(message_t * msg, void * payload, uint8_t len){
#line 78
  nx_struct message_t *__nesc_result;
#line 78

#line 78
  __nesc_result = CC2420ActiveMessageP__SubReceive__receive(msg, payload, len);
#line 78

#line 78
  return __nesc_result;
#line 78
}
#line 78
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
inline static cc2420_metadata_t * CC2420TinyosNetworkP__CC2420PacketBody__getMetadata(message_t * msg){
#line 53
  nx_struct cc2420_metadata *__nesc_result;
#line 53

#line 53
  __nesc_result = CC2420PacketP__CC2420PacketBody__getMetadata(msg);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 119 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/packet/CC2420PacketP.nc"
static inline uint8_t CC2420PacketP__CC2420Packet__getNetwork(message_t * p_msg)
#line 119
{



  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      unsigned char __nesc_temp = 
#line 124
      *CC2420PacketP__getNetwork(p_msg);

      {
#line 124
        __nesc_atomic_end(__nesc_atomic); 
#line 124
        return __nesc_temp;
      }
    }
#line 126
    __nesc_atomic_end(__nesc_atomic); }
}

# 75 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Packet.nc"
inline static uint8_t CC2420TinyosNetworkP__CC2420Packet__getNetwork(message_t * p_msg){
#line 75
  unsigned char __nesc_result;
#line 75

#line 75
  __nesc_result = CC2420PacketP__CC2420Packet__getNetwork(p_msg);
#line 75

#line 75
  return __nesc_result;
#line 75
}
#line 75
# 158 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
static inline message_t *CC2420TinyosNetworkP__SubReceive__receive(message_t *msg, void *payload, uint8_t len)
#line 158
{
  uint8_t network = CC2420TinyosNetworkP__CC2420Packet__getNetwork(msg);


  if (! __nesc_ntoh_int8(CC2420TinyosNetworkP__CC2420PacketBody__getMetadata(msg)->crc.nxdata)) {
      return msg;
    }



  if (network == 0x3f) {
      return CC2420TinyosNetworkP__ActiveReceive__receive(msg, payload, len);
    }
  else 
#line 170
    {
      return CC2420TinyosNetworkP__BareReceive__receive(msg, 
      CC2420TinyosNetworkP__BareSend__getPayload(msg, len), 
      len + sizeof(cc2420_header_t ));
    }
}

# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
inline static message_t * UniqueReceiveP__Receive__receive(message_t * msg, void * payload, uint8_t len){
#line 78
  nx_struct message_t *__nesc_result;
#line 78

#line 78
  __nesc_result = CC2420TinyosNetworkP__SubReceive__receive(msg, payload, len);
#line 78

#line 78
  return __nesc_result;
#line 78
}
#line 78
# 138 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/unique/UniqueReceiveP.nc"
static inline void UniqueReceiveP__insert(uint16_t msgSource, uint8_t msgDsn)
#line 138
{
  uint8_t element = UniqueReceiveP__recycleSourceElement;
  bool increment = FALSE;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 142
    {
      if (element == UniqueReceiveP__INVALID_ELEMENT || UniqueReceiveP__writeIndex == element) {

          element = UniqueReceiveP__writeIndex;
          increment = TRUE;
        }

      UniqueReceiveP__receivedMessages[element].source = msgSource;
      UniqueReceiveP__receivedMessages[element].dsn = msgDsn;
      if (increment) {
          UniqueReceiveP__writeIndex++;
          UniqueReceiveP__writeIndex %= 4;
        }
    }
#line 155
    __nesc_atomic_end(__nesc_atomic); }
}

#line 192
static inline message_t *UniqueReceiveP__DuplicateReceive__default__receive(message_t *msg, void *payload, uint8_t len)
#line 192
{
  return msg;
}

# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
inline static message_t * UniqueReceiveP__DuplicateReceive__receive(message_t * msg, void * payload, uint8_t len){
#line 78
  nx_struct message_t *__nesc_result;
#line 78

#line 78
  __nesc_result = UniqueReceiveP__DuplicateReceive__default__receive(msg, payload, len);
#line 78

#line 78
  return __nesc_result;
#line 78
}
#line 78
# 112 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/unique/UniqueReceiveP.nc"
static inline bool UniqueReceiveP__hasSeen(uint16_t msgSource, uint8_t msgDsn)
#line 112
{
  int i;

#line 114
  UniqueReceiveP__recycleSourceElement = UniqueReceiveP__INVALID_ELEMENT;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 116
    {
      for (i = 0; i < 4; i++) {
          if (UniqueReceiveP__receivedMessages[i].source == msgSource) {
              if (UniqueReceiveP__receivedMessages[i].dsn == msgDsn) {

                  {
                    unsigned char __nesc_temp = 
#line 121
                    TRUE;

                    {
#line 121
                      __nesc_atomic_end(__nesc_atomic); 
#line 121
                      return __nesc_temp;
                    }
                  }
                }
#line 124
              UniqueReceiveP__recycleSourceElement = i;
            }
        }
    }
#line 127
    __nesc_atomic_end(__nesc_atomic); }

  return FALSE;
}

# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
inline static cc2420_header_t * UniqueReceiveP__CC2420PacketBody__getHeader(message_t * msg){
#line 42
  nx_struct cc2420_header *__nesc_result;
#line 42

#line 42
  __nesc_result = CC2420PacketP__CC2420PacketBody__getHeader(msg);
#line 42

#line 42
  return __nesc_result;
#line 42
}
#line 42
# 165 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/unique/UniqueReceiveP.nc"
static inline uint16_t UniqueReceiveP__getSourceKey(message_t * msg)
#line 165
{
  cc2420_header_t *hdr = UniqueReceiveP__CC2420PacketBody__getHeader(msg);
  int s_mode = (__nesc_ntoh_leuint16(hdr->fcf.nxdata) >> IEEE154_FCF_SRC_ADDR_MODE) & 0x3;
  int d_mode = (__nesc_ntoh_leuint16(hdr->fcf.nxdata) >> IEEE154_FCF_DEST_ADDR_MODE) & 0x3;
  int s_offset = 2;
#line 169
  int s_len = 2;
  uint16_t key = 0;
  uint8_t *current = (uint8_t *)& hdr->dest;
  int i;

  if (s_mode == IEEE154_ADDR_EXT) {
      s_len = 8;
    }
  if (d_mode == IEEE154_ADDR_EXT) {
      s_offset = 8;
    }

  current += s_offset;

  for (i = 0; i < s_len; i++) {
      key += current[i];
    }
  return key;
}

#line 86
static inline message_t *UniqueReceiveP__SubReceive__receive(message_t *msg, void *payload, 
uint8_t len)
#line 87
{

  uint16_t msgSource = UniqueReceiveP__getSourceKey(msg);
  uint8_t msgDsn = __nesc_ntoh_leuint8(UniqueReceiveP__CC2420PacketBody__getHeader(msg)->dsn.nxdata);

  if (UniqueReceiveP__hasSeen(msgSource, msgDsn)) {
      return UniqueReceiveP__DuplicateReceive__receive(msg, payload, len);
    }
  else 
#line 94
    {
      UniqueReceiveP__insert(msgSource, msgDsn);
      return UniqueReceiveP__Receive__receive(msg, payload, len);
    }
}

# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
inline static message_t * CC2420ReceiveP__Receive__receive(message_t * msg, void * payload, uint8_t len){
#line 78
  nx_struct message_t *__nesc_result;
#line 78

#line 78
  __nesc_result = UniqueReceiveP__SubReceive__receive(msg, payload, len);
#line 78

#line 78
  return __nesc_result;
#line 78
}
#line 78
# 298 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline ieee_eui64_t CC2420ControlP__CC2420Config__getExtAddr(void )
#line 298
{
  return CC2420ControlP__m_ext_addr;
}

# 66 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Config.nc"
inline static ieee_eui64_t CC2420ReceiveP__CC2420Config__getExtAddr(void ){
#line 66
  struct ieee_eui64 __nesc_result;
#line 66

#line 66
  __nesc_result = CC2420ControlP__CC2420Config__getExtAddr();
#line 66

#line 66
  return __nesc_result;
#line 66
}
#line 66





inline static uint16_t CC2420ReceiveP__CC2420Config__getShortAddr(void ){
#line 71
  unsigned short __nesc_result;
#line 71

#line 71
  __nesc_result = CC2420ControlP__CC2420Config__getShortAddr();
#line 71

#line 71
  return __nesc_result;
#line 71
}
#line 71
# 355 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline bool CC2420ControlP__CC2420Config__isAddressRecognitionEnabled(void )
#line 355
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 356
    {
      unsigned char __nesc_temp = 
#line 356
      CC2420ControlP__addressRecognition;

      {
#line 356
        __nesc_atomic_end(__nesc_atomic); 
#line 356
        return __nesc_temp;
      }
    }
#line 358
    __nesc_atomic_end(__nesc_atomic); }
}

# 93 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Config.nc"
inline static bool CC2420ReceiveP__CC2420Config__isAddressRecognitionEnabled(void ){
#line 93
  unsigned char __nesc_result;
#line 93

#line 93
  __nesc_result = CC2420ControlP__CC2420Config__isAddressRecognitionEnabled();
#line 93

#line 93
  return __nesc_result;
#line 93
}
#line 93
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
inline static cc2420_header_t * CC2420ReceiveP__CC2420PacketBody__getHeader(message_t * msg){
#line 42
  nx_struct cc2420_header *__nesc_result;
#line 42

#line 42
  __nesc_result = CC2420PacketP__CC2420PacketBody__getHeader(msg);
#line 42

#line 42
  return __nesc_result;
#line 42
}
#line 42
# 824 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static inline bool CC2420ReceiveP__passesAddressCheck(message_t *msg)
#line 824
{
  cc2420_header_t *header = CC2420ReceiveP__CC2420PacketBody__getHeader(msg);
  int mode = (__nesc_ntoh_leuint16(header->fcf.nxdata) >> IEEE154_FCF_DEST_ADDR_MODE) & 3;
  ieee_eui64_t *ext_addr;

  if (!CC2420ReceiveP__CC2420Config__isAddressRecognitionEnabled()) {
      return TRUE;
    }

  if (mode == IEEE154_ADDR_SHORT) {
      return __nesc_ntoh_leuint16(header->dest.nxdata) == CC2420ReceiveP__CC2420Config__getShortAddr()
       || __nesc_ntoh_leuint16(header->dest.nxdata) == IEEE154_BROADCAST_ADDR;
    }
  else {
#line 836
    if (mode == IEEE154_ADDR_EXT) {
        ieee_eui64_t local_addr = CC2420ReceiveP__CC2420Config__getExtAddr();

#line 838
        ext_addr = (ieee_eui64_t * )& header->dest;
        return memcmp(ext_addr->data, local_addr.data, IEEE_EUI64_LENGTH) == 0;
      }
    else 
#line 840
      {

        return FALSE;
      }
    }
}

# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
inline static cc2420_metadata_t * CC2420ReceiveP__CC2420PacketBody__getMetadata(message_t * msg){
#line 53
  nx_struct cc2420_metadata *__nesc_result;
#line 53

#line 53
  __nesc_result = CC2420PacketP__CC2420PacketBody__getMetadata(msg);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 676 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static inline void CC2420ReceiveP__receiveDone_task__runTask(void )
#line 676
{
  cc2420_metadata_t *metadata = CC2420ReceiveP__CC2420PacketBody__getMetadata(CC2420ReceiveP__m_p_rx_buf);
  cc2420_header_t *header = CC2420ReceiveP__CC2420PacketBody__getHeader(CC2420ReceiveP__m_p_rx_buf);
  uint8_t length = __nesc_ntoh_leuint8(header->length.nxdata);
  uint8_t tmpLen __attribute((unused))  = sizeof(message_t ) - ((unsigned short )& ((message_t *)0)->data - sizeof(cc2420_header_t ));
  uint8_t * buf = (uint8_t * )header;

  __nesc_hton_int8(metadata->crc.nxdata, buf[length] >> 7);
  __nesc_hton_uint8(metadata->lqi.nxdata, buf[length] & 0x7f);
  __nesc_hton_uint8(metadata->rssi.nxdata, buf[length - 1]);

  if (CC2420ReceiveP__passesAddressCheck(CC2420ReceiveP__m_p_rx_buf) && length >= CC2420_SIZE) {
#line 701
      CC2420ReceiveP__m_p_rx_buf = CC2420ReceiveP__Receive__receive(CC2420ReceiveP__m_p_rx_buf, CC2420ReceiveP__m_p_rx_buf->data, 
      length - CC2420_SIZE);
    }
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 704
    CC2420ReceiveP__receivingPacket = FALSE;
#line 704
    __nesc_atomic_end(__nesc_atomic); }
  CC2420ReceiveP__waitForNextPacket();
}

# 95 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static inline void CC2420SpiP__ChipSpiResource__abortRelease(void )
#line 95
{
  /* atomic removed: atomic calls only */
#line 96
  CC2420SpiP__release = FALSE;
}

# 31 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/ChipSpiResource.nc"
inline static void CC2420TransmitP__ChipSpiResource__abortRelease(void ){
#line 31
  CC2420SpiP__ChipSpiResource__abortRelease();
#line 31
}
#line 31
# 377 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline void CC2420TransmitP__ChipSpiResource__releasing(void )
#line 377
{
  if (CC2420TransmitP__abortSpiRelease) {
      CC2420TransmitP__ChipSpiResource__abortRelease();
    }
}

# 24 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/ChipSpiResource.nc"
inline static void CC2420SpiP__ChipSpiResource__releasing(void ){
#line 24
  CC2420TransmitP__ChipSpiResource__releasing();
#line 24
}
#line 24
# 52 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerState.nc"
inline static void Atm128SpiP__McuPowerState__update(void ){
#line 52
  McuSleepC__McuPowerState__update();
#line 52
}
#line 52
# 112 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
static inline void HplAtm128SpiP__SPI__sleep(void )
#line 112
{
}

# 89 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
inline static void Atm128SpiP__Spi__sleep(void ){
#line 89
  HplAtm128SpiP__SPI__sleep();
#line 89
}
#line 89
#line 116
inline static void Atm128SpiP__Spi__enableSpi(bool busOn){
#line 116
  HplAtm128SpiP__SPI__enableSpi(busOn);
#line 116
}
#line 116
# 165 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128SpiP.nc"
static inline void Atm128SpiP__stopSpi(void )
#line 165
{
  Atm128SpiP__Spi__enableSpi(FALSE);
  /* atomic removed: atomic calls only */
#line 167
  {
    Atm128SpiP__Spi__sleep();
  }
  Atm128SpiP__McuPowerState__update();
}

#line 396
static inline void Atm128SpiP__ResourceConfigure__unconfigure(uint8_t id)
#line 396
{
  Atm128SpiP__stopSpi();
}

# 65 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
inline static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceConfigure__unconfigure(uint8_t arg_0x7f7cba82d730){
#line 65
  Atm128SpiP__ResourceConfigure__unconfigure(arg_0x7f7cba82d730);
#line 65
}
#line 65
# 68 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
static inline resource_client_id_t /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__dequeue(void )
#line 68
{
  /* atomic removed: atomic calls only */
#line 69
  {
    if (/*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qHead != /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__NO_ENTRY) {
        uint8_t id = /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qHead;

#line 72
        /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qHead = /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__resQ[/*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qHead];
        if (/*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qHead == /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__NO_ENTRY) {
          /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qTail = /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__NO_ENTRY;
          }
#line 75
        /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__resQ[id] = /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__NO_ENTRY;
        {
          unsigned char __nesc_temp = 
#line 76
          id;

#line 76
          return __nesc_temp;
        }
      }
#line 78
    {
      unsigned char __nesc_temp = 
#line 78
      /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__NO_ENTRY;

#line 78
      return __nesc_temp;
    }
  }
}

# 70 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
inline static resource_client_id_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Queue__dequeue(void ){
#line 70
  unsigned char __nesc_result;
#line 70

#line 70
  __nesc_result = /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__dequeue();
#line 70

#line 70
  return __nesc_result;
#line 70
}
#line 70
# 60 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
static inline bool /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEmpty(void )
#line 60
{
  /* atomic removed: atomic calls only */
#line 61
  {
    unsigned char __nesc_temp = 
#line 61
    /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__qHead == /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__NO_ENTRY;

#line 61
    return __nesc_temp;
  }
}

# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
inline static bool /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Queue__isEmpty(void ){
#line 53
  unsigned char __nesc_result;
#line 53

#line 53
  __nesc_result = /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEmpty();
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 96 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
static inline error_t /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__release(uint8_t id)
#line 96
{
  /* atomic removed: atomic calls only */
#line 97
  {
    if (/*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__state == /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__RES_BUSY && /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__resId == id) {
        if (/*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Queue__isEmpty() == FALSE) {
            /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__resId = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Queue__dequeue();
            /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__state = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__RES_GRANTING;
            /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__grantedTask__postTask();
          }
        else {
            /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__resId = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__NO_RES;
            /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__state = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__RES_IDLE;
          }
        /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceConfigure__unconfigure(id);
        {
          enum __nesc_unnamed4242 __nesc_temp = 
#line 109
          SUCCESS;

#line 109
          return __nesc_temp;
        }
      }
  }
#line 112
  return FAIL;
}

# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t HplCC2420SpiP__SubResource__release(void ){
#line 120
  enum __nesc_unnamed4242 __nesc_result;
#line 120

#line 120
  __nesc_result = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__release(0U);
#line 120

#line 120
  return __nesc_result;
#line 120
}
#line 120
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__set(void )
#line 55
{
#line 55
  * (volatile uint8_t * )56U |= 1 << 0;
}

# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void HplCC2420SpiP__SS__set(void ){
#line 40
  /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__set();
#line 40
}
#line 40
# 75 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/chips/cc2420/HplCC2420SpiP.nc"
static inline error_t HplCC2420SpiP__Resource__release(void )
{
  if (HplCC2420SpiP__SubResource__isOwner()) {
    HplCC2420SpiP__SS__set();
    }
  return HplCC2420SpiP__SubResource__release();
}

# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420SpiP__SpiResource__release(void ){
#line 120
  enum __nesc_unnamed4242 __nesc_result;
#line 120

#line 120
  __nesc_result = HplCC2420SpiP__Resource__release();
#line 120

#line 120
  return __nesc_result;
#line 120
}
#line 120
# 178 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static inline bool CC2420SpiP__Resource__isOwner(uint8_t id)
#line 178
{
  /* atomic removed: atomic calls only */
#line 179
  {
    unsigned char __nesc_temp = 
#line 179
    CC2420SpiP__m_holder == id;

#line 179
    return __nesc_temp;
  }
}

# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static bool CC2420ReceiveP__SpiResource__isOwner(void ){
#line 128
  unsigned char __nesc_result;
#line 128

#line 128
  __nesc_result = CC2420SpiP__Resource__isOwner(/*CC2420ReceiveC.Spi*/CC2420SpiC__4__CLIENT_ID);
#line 128

#line 128
  return __nesc_result;
#line 128
}
#line 128
#line 97
inline static error_t CC2420ReceiveP__SpiResource__immediateRequest(void ){
#line 97
  enum __nesc_unnamed4242 __nesc_result;
#line 97

#line 97
  __nesc_result = CC2420SpiP__Resource__immediateRequest(/*CC2420ReceiveC.Spi*/CC2420SpiC__4__CLIENT_ID);
#line 97

#line 97
  return __nesc_result;
#line 97
}
#line 97
#line 88
inline static error_t CC2420ReceiveP__SpiResource__request(void ){
#line 88
  enum __nesc_unnamed4242 __nesc_result;
#line 88

#line 88
  __nesc_result = CC2420SpiP__Resource__request(/*CC2420ReceiveC.Spi*/CC2420SpiC__4__CLIENT_ID);
#line 88

#line 88
  return __nesc_result;
#line 88
}
#line 88
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t CC2420SpiP__grant__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(CC2420SpiP__grant);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 184 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static inline void CC2420SpiP__SpiResource__granted(void )
#line 184
{
  CC2420SpiP__grant__postTask();
}

# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static void HplCC2420SpiP__Resource__granted(void ){
#line 102
  CC2420SpiP__SpiResource__granted();
#line 102
}
#line 102
# 67 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/chips/cc2420/HplCC2420SpiP.nc"
static inline void HplCC2420SpiP__SubResource__granted(void )
{
  HplCC2420SpiP__SS__makeOutput();
  HplCC2420SpiP__SS__clr();

  HplCC2420SpiP__Resource__granted();
}

# 153 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
static inline void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__default__granted(uint8_t id)
#line 153
{
}

# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__granted(uint8_t arg_0x7f7cba830df0){
#line 102
  switch (arg_0x7f7cba830df0) {
#line 102
    case 0U:
#line 102
      HplCC2420SpiP__SubResource__granted();
#line 102
      break;
#line 102
    default:
#line 102
      /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__default__granted(arg_0x7f7cba830df0);
#line 102
      break;
#line 102
    }
#line 102
}
#line 102
# 144 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
static inline void /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__grantedTask__runTask(void )
#line 144
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 145
    {
      /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__state = /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__RES_BUSY;
      /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__ResourceConfigure__configure(/*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__resId);
    }
#line 148
    __nesc_atomic_end(__nesc_atomic); }
  /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__granted(/*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__resId);
}

# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
inline static void Atm128SpiP__SpiPacket__sendDone(uint8_t * txBuf, uint8_t * rxBuf, uint16_t len, error_t error){
#line 88
  CC2420SpiP__SpiPacket__sendDone(txBuf, rxBuf, len, error);
#line 88
}
#line 88
# 294 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128SpiP.nc"
static inline void Atm128SpiP__zeroTask__runTask(void )
#line 294
{
  uint16_t myLen;
  uint8_t * rx;
  uint8_t * tx;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 299
    {
      myLen = Atm128SpiP__len;
      rx = Atm128SpiP__rxBuffer;
      tx = Atm128SpiP__txBuffer;
      Atm128SpiP__rxBuffer = (void *)0;
      Atm128SpiP__txBuffer = (void *)0;
      Atm128SpiP__len = 0;
      Atm128SpiP__pos = 0;
      Atm128SpiP__SpiPacket__sendDone(tx, rx, myLen, SUCCESS);
    }
#line 308
    __nesc_atomic_end(__nesc_atomic); }
}

# 486 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline void CC2420TransmitP__TXFIFO__readDone(uint8_t *tx_buf, uint8_t tx_len, 
error_t error)
#line 487
{
}

# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420ReceiveP__SpiResource__release(void ){
#line 120
  enum __nesc_unnamed4242 __nesc_result;
#line 120

#line 120
  __nesc_result = CC2420SpiP__Resource__release(/*CC2420ReceiveC.Spi*/CC2420SpiC__4__CLIENT_ID);
#line 120

#line 120
  return __nesc_result;
#line 120
}
#line 120
# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ReceiveP__CSN__set(void ){
#line 40
  /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__set();
#line 40
}
#line 40
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t CC2420ReceiveP__receiveDone_task__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(CC2420ReceiveP__receiveDone_task);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
inline static cc2420_metadata_t * CC2420TransmitP__CC2420PacketBody__getMetadata(message_t * msg){
#line 53
  nx_struct cc2420_metadata *__nesc_result;
#line 53

#line 53
  __nesc_result = CC2420PacketP__CC2420PacketBody__getMetadata(msg);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 148 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline void HplAtm128Timer1P__CompareA__stop(void )
#line 148
{
#line 148
  * (volatile uint8_t *)(0x37 + 0x20) &= ~(1 << 4);
}

# 68 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__stop(void ){
#line 68
  HplAtm128Timer1P__CompareA__stop();
#line 68
}
#line 68
# 74 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__stop(void )
#line 74
{
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__stop();
}

# 73 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__stop(void ){
#line 73
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__stop();
#line 73
}
#line 73
# 102 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__stop(void )
{
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__stop();
}

# 73 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void CC2420TransmitP__BackoffTimer__stop(void ){
#line 73
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__stop();
#line 73
}
#line 73
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420PacketBody.nc"
inline static cc2420_header_t * CC2420TransmitP__CC2420PacketBody__getHeader(message_t * msg){
#line 42
  nx_struct cc2420_header *__nesc_result;
#line 42

#line 42
  __nesc_result = CC2420PacketP__CC2420PacketBody__getHeader(msg);
#line 42

#line 42
  return __nesc_result;
#line 42
}
#line 42
# 389 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline void CC2420TransmitP__CC2420Receive__receive(uint8_t type, message_t *ack_msg)
#line 389
{
  cc2420_header_t *ack_header;
  cc2420_header_t *msg_header;
  cc2420_metadata_t *msg_metadata;
  uint8_t *ack_buf;
  uint8_t length;

  if (type == IEEE154_TYPE_ACK && CC2420TransmitP__m_msg) {
      ack_header = CC2420TransmitP__CC2420PacketBody__getHeader(ack_msg);
      msg_header = CC2420TransmitP__CC2420PacketBody__getHeader(CC2420TransmitP__m_msg);

      if (CC2420TransmitP__m_state == CC2420TransmitP__S_ACK_WAIT && __nesc_ntoh_leuint8(msg_header->dsn.nxdata) == __nesc_ntoh_leuint8(ack_header->dsn.nxdata)) {
          CC2420TransmitP__BackoffTimer__stop();

          msg_metadata = CC2420TransmitP__CC2420PacketBody__getMetadata(CC2420TransmitP__m_msg);
          ack_buf = (uint8_t *)ack_header;
          length = __nesc_ntoh_leuint8(ack_header->length.nxdata);

          __nesc_hton_int8(msg_metadata->ack.nxdata, TRUE);
          __nesc_hton_uint8(msg_metadata->rssi.nxdata, ack_buf[length - 1]);
          __nesc_hton_uint8(msg_metadata->lqi.nxdata, ack_buf[length] & 0x7f);
          CC2420TransmitP__signalDone(SUCCESS);
        }
    }
}

# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Receive.nc"
inline static void CC2420ReceiveP__CC2420Receive__receive(uint8_t type, message_t * message){
#line 63
  CC2420TransmitP__CC2420Receive__receive(type, message);
#line 63
}
#line 63
# 70 "/home/wtiberti/WSN/tinyos/tos/interfaces/PacketTimeStamp.nc"
inline static void CC2420ReceiveP__PacketTimeStamp__clear(message_t * msg){
#line 70
  CC2420PacketP__PacketTimeStamp32khz__clear(msg);
#line 70
}
#line 70








inline static void CC2420ReceiveP__PacketTimeStamp__set(message_t * msg, CC2420ReceiveP__PacketTimeStamp__size_type value){
#line 78
  CC2420PacketP__PacketTimeStamp32khz__set(msg, value);
#line 78
}
#line 78
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline bool /*HplAtm128GeneralIOC.PortE.Bit6*/HplAtm128GeneralIOPinP__38__IO__get(void )
#line 54
{
#line 54
  return (* (volatile uint8_t * )33U & (1 << 6)) != 0;
}

# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static bool CC2420ReceiveP__FIFOP__get(void ){
#line 43
  unsigned char __nesc_result;
#line 43

#line 43
  __nesc_result = /*HplAtm128GeneralIOC.PortE.Bit6*/HplAtm128GeneralIOPinP__38__IO__get();
#line 43

#line 43
  return __nesc_result;
#line 43
}
#line 43
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline bool /*HplAtm128GeneralIOC.PortB.Bit7*/HplAtm128GeneralIOPinP__15__IO__get(void )
#line 54
{
#line 54
  return (* (volatile uint8_t * )54U & (1 << 7)) != 0;
}

# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static bool CC2420ReceiveP__FIFO__get(void ){
#line 43
  unsigned char __nesc_result;
#line 43

#line 43
  __nesc_result = /*HplAtm128GeneralIOC.PortB.Bit7*/HplAtm128GeneralIOPinP__15__IO__get();
#line 43

#line 43
  return __nesc_result;
#line 43
}
#line 43
# 209 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static inline error_t CC2420SpiP__Fifo__continueRead(uint8_t addr, uint8_t *data, 
uint8_t len)
#line 210
{
  return CC2420SpiP__SpiPacket__send((void *)0, data, len);
}

# 62 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
inline static error_t CC2420ReceiveP__RXFIFO__continueRead(uint8_t * data, uint8_t length){
#line 62
  enum __nesc_unnamed4242 __nesc_result;
#line 62

#line 62
  __nesc_result = CC2420SpiP__Fifo__continueRead(CC2420_RXFIFO, data, length);
#line 62

#line 62
  return __nesc_result;
#line 62
}
#line 62
#line 51
inline static cc2420_status_t CC2420ReceiveP__RXFIFO__beginRead(uint8_t * data, uint8_t length){
#line 51
  unsigned char __nesc_result;
#line 51

#line 51
  __nesc_result = CC2420SpiP__Fifo__beginRead(CC2420_RXFIFO, data, length);
#line 51

#line 51
  return __nesc_result;
#line 51
}
#line 51
# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ReceiveP__CSN__clr(void ){
#line 41
  /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__clr();
#line 41
}
#line 41
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
inline static cc2420_status_t CC2420ReceiveP__SACK__strobe(void ){
#line 53
  unsigned char __nesc_result;
#line 53

#line 53
  __nesc_result = CC2420SpiP__Strobe__strobe(CC2420_SACK);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 382 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline bool CC2420ControlP__CC2420Config__isHwAutoAckDefault(void )
#line 382
{
  /* atomic removed: atomic calls only */
#line 383
  {
    unsigned char __nesc_temp = 
#line 383
    CC2420ControlP__hwAutoAckDefault;

#line 383
    return __nesc_temp;
  }
}

# 112 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Config.nc"
inline static bool CC2420ReceiveP__CC2420Config__isHwAutoAckDefault(void ){
#line 112
  unsigned char __nesc_result;
#line 112

#line 112
  __nesc_result = CC2420ControlP__CC2420Config__isHwAutoAckDefault();
#line 112

#line 112
  return __nesc_result;
#line 112
}
#line 112
# 389 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline bool CC2420ControlP__CC2420Config__isAutoAckEnabled(void )
#line 389
{
  /* atomic removed: atomic calls only */
#line 390
  {
    unsigned char __nesc_temp = 
#line 390
    CC2420ControlP__autoAckEnabled;

#line 390
    return __nesc_temp;
  }
}

# 117 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Config.nc"
inline static bool CC2420ReceiveP__CC2420Config__isAutoAckEnabled(void ){
#line 117
  unsigned char __nesc_result;
#line 117

#line 117
  __nesc_result = CC2420ControlP__CC2420Config__isAutoAckEnabled();
#line 117

#line 117
  return __nesc_result;
#line 117
}
#line 117
# 530 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static inline void CC2420ReceiveP__RXFIFO__readDone(uint8_t *rx_buf, uint8_t rx_len, 
error_t error)
#line 531
{
  cc2420_header_t *header = CC2420ReceiveP__CC2420PacketBody__getHeader(CC2420ReceiveP__m_p_rx_buf);
  uint8_t tmpLen __attribute((unused))  = sizeof(message_t ) - ((unsigned short )& ((message_t *)0)->data - sizeof(cc2420_header_t ));
  uint8_t * buf = (uint8_t * )header;

#line 535
  CC2420ReceiveP__rxFrameLength = buf[0];

  switch (CC2420ReceiveP__m_state) {

      case CC2420ReceiveP__S_RX_LENGTH: 
        CC2420ReceiveP__m_state = CC2420ReceiveP__S_RX_FCF;



      if (CC2420ReceiveP__rxFrameLength + 1 > CC2420ReceiveP__m_bytes_left) 



        {

          CC2420ReceiveP__flush();
        }
      else {
          if (!CC2420ReceiveP__FIFO__get() && !CC2420ReceiveP__FIFOP__get()) {
              CC2420ReceiveP__m_bytes_left -= CC2420ReceiveP__rxFrameLength + 1;
            }

          if (CC2420ReceiveP__rxFrameLength <= MAC_PACKET_SIZE) {
              if (CC2420ReceiveP__rxFrameLength > 0) {
                  if (CC2420ReceiveP__rxFrameLength > CC2420ReceiveP__SACK_HEADER_LENGTH) {

                      CC2420ReceiveP__RXFIFO__continueRead(buf + 1, CC2420ReceiveP__SACK_HEADER_LENGTH);
                    }
                  else {

                      CC2420ReceiveP__m_state = CC2420ReceiveP__S_RX_PAYLOAD;
                      CC2420ReceiveP__RXFIFO__continueRead(buf + 1, CC2420ReceiveP__rxFrameLength);
                    }
                }
              else {
                  /* atomic removed: atomic calls only */
                  CC2420ReceiveP__receivingPacket = FALSE;
                  CC2420ReceiveP__CSN__set();
                  CC2420ReceiveP__SpiResource__release();
                  CC2420ReceiveP__waitForNextPacket();
                }
            }
          else {

              CC2420ReceiveP__flush();
            }
        }
      break;

      case CC2420ReceiveP__S_RX_FCF: 
        CC2420ReceiveP__m_state = CC2420ReceiveP__S_RX_PAYLOAD;










      if (CC2420ReceiveP__CC2420Config__isAutoAckEnabled() && !CC2420ReceiveP__CC2420Config__isHwAutoAckDefault()) {



          if (((__nesc_ntoh_leuint16(
#line 597
          header->fcf.nxdata) >> IEEE154_FCF_ACK_REQ) & 0x01) == 1
           && (__nesc_ntoh_leuint16(header->dest.nxdata) == CC2420ReceiveP__CC2420Config__getShortAddr()
           || __nesc_ntoh_leuint16(header->dest.nxdata) == AM_BROADCAST_ADDR)
           && ((__nesc_ntoh_leuint16(header->fcf.nxdata) >> IEEE154_FCF_FRAME_TYPE) & 7) == IEEE154_TYPE_DATA) {

              CC2420ReceiveP__CSN__set();
              CC2420ReceiveP__CSN__clr();
              CC2420ReceiveP__SACK__strobe();
              CC2420ReceiveP__CSN__set();
              CC2420ReceiveP__CSN__clr();
              CC2420ReceiveP__RXFIFO__beginRead(buf + 1 + CC2420ReceiveP__SACK_HEADER_LENGTH, 
              CC2420ReceiveP__rxFrameLength - CC2420ReceiveP__SACK_HEADER_LENGTH);
              return;
            }
        }

      CC2420ReceiveP__RXFIFO__continueRead(buf + 1 + CC2420ReceiveP__SACK_HEADER_LENGTH, 
      CC2420ReceiveP__rxFrameLength - CC2420ReceiveP__SACK_HEADER_LENGTH);
      break;

      case CC2420ReceiveP__S_RX_PAYLOAD: 

        CC2420ReceiveP__CSN__set();
      if (!CC2420ReceiveP__m_missed_packets) {

          CC2420ReceiveP__SpiResource__release();
        }




      if ((((
#line 626
      CC2420ReceiveP__m_missed_packets && CC2420ReceiveP__FIFO__get()) || !CC2420ReceiveP__FIFOP__get())
       || !CC2420ReceiveP__m_timestamp_size)
       || CC2420ReceiveP__rxFrameLength <= 10) {
          CC2420ReceiveP__PacketTimeStamp__clear(CC2420ReceiveP__m_p_rx_buf);
        }
      else {
          if (CC2420ReceiveP__m_timestamp_size == 1) {
            CC2420ReceiveP__PacketTimeStamp__set(CC2420ReceiveP__m_p_rx_buf, CC2420ReceiveP__m_timestamp_queue[CC2420ReceiveP__m_timestamp_head]);
            }
#line 634
          CC2420ReceiveP__m_timestamp_head = (CC2420ReceiveP__m_timestamp_head + 1) % CC2420ReceiveP__TIMESTAMP_QUEUE_SIZE;
          CC2420ReceiveP__m_timestamp_size--;

          if (CC2420ReceiveP__m_timestamp_size > 0) {
              CC2420ReceiveP__PacketTimeStamp__clear(CC2420ReceiveP__m_p_rx_buf);
              CC2420ReceiveP__m_timestamp_head = 0;
              CC2420ReceiveP__m_timestamp_size = 0;
            }
        }



      if (buf[CC2420ReceiveP__rxFrameLength] >> 7 && rx_buf) {
          uint8_t type = (__nesc_ntoh_leuint16(header->fcf.nxdata) >> IEEE154_FCF_FRAME_TYPE) & 7;

#line 648
          CC2420ReceiveP__CC2420Receive__receive(type, CC2420ReceiveP__m_p_rx_buf);
          if (type == IEEE154_TYPE_DATA) {
              CC2420ReceiveP__receiveDone_task__postTask();
              return;
            }
        }

      CC2420ReceiveP__waitForNextPacket();
      break;

      default: /* atomic removed: atomic calls only */
        CC2420ReceiveP__receivingPacket = FALSE;
      CC2420ReceiveP__CSN__set();
      CC2420ReceiveP__SpiResource__release();
      break;
    }
}

# 370 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static inline void CC2420SpiP__Fifo__default__readDone(uint8_t addr, uint8_t *rx_buf, uint8_t rx_len, error_t error)
#line 370
{
}

# 71 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
inline static void CC2420SpiP__Fifo__readDone(uint8_t arg_0x7f7cba9baa00, uint8_t * data, uint8_t length, error_t error){
#line 71
  switch (arg_0x7f7cba9baa00) {
#line 71
    case CC2420_TXFIFO:
#line 71
      CC2420TransmitP__TXFIFO__readDone(data, length, error);
#line 71
      break;
#line 71
    case CC2420_RXFIFO:
#line 71
      CC2420ReceiveP__RXFIFO__readDone(data, length, error);
#line 71
      break;
#line 71
    default:
#line 71
      CC2420SpiP__Fifo__default__readDone(arg_0x7f7cba9baa00, data, length, error);
#line 71
      break;
#line 71
    }
#line 71
}
#line 71
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
inline static cc2420_status_t CC2420ReceiveP__SFLUSHRX__strobe(void ){
#line 53
  unsigned char __nesc_result;
#line 53

#line 53
  __nesc_result = CC2420SpiP__Strobe__strobe(CC2420_SFLUSHRX);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 102 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static inline error_t CC2420SpiP__ChipSpiResource__attemptRelease(void )
#line 102
{
  return CC2420SpiP__attemptRelease();
}

# 39 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/ChipSpiResource.nc"
inline static error_t CC2420TransmitP__ChipSpiResource__attemptRelease(void ){
#line 39
  enum __nesc_unnamed4242 __nesc_result;
#line 39

#line 39
  __nesc_result = CC2420SpiP__ChipSpiResource__attemptRelease();
#line 39

#line 39
  return __nesc_result;
#line 39
}
#line 39
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Counter__size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Counter__get(void ){
#line 64
  unsigned long __nesc_result;
#line 64

#line 64
  __nesc_result = /*Counter32khz32C.Transform32*/TransformCounterC__0__Counter__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64
# 86 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__getNow(void )
{
  return /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Counter__get();
}

#line 157
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__start(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type dt)
{
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__getNow(), dt);
}

# 66 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void CC2420TransmitP__BackoffTimer__start(CC2420TransmitP__BackoffTimer__size_type dt){
#line 66
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__start(dt);
#line 66
}
#line 66
# 293 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void CC2420ActiveMessageP__RadioBackoff__default__requestInitialBackoff(am_id_t id, 
message_t *msg)
#line 294
{
}

# 81 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
inline static void CC2420ActiveMessageP__RadioBackoff__requestInitialBackoff(am_id_t arg_0x7f7cba393700, message_t * msg){
#line 81
    CC2420ActiveMessageP__RadioBackoff__default__requestInitialBackoff(arg_0x7f7cba393700, msg);
#line 81
}
#line 81
# 241 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void CC2420ActiveMessageP__SubBackoff__requestInitialBackoff(message_t *msg)
#line 241
{
  CC2420ActiveMessageP__RadioBackoff__requestInitialBackoff(__nesc_ntoh_leuint8(((cc2420_header_t * )((uint8_t *)msg + (unsigned short )& ((message_t *)0)->data - sizeof(cc2420_header_t )))->type.nxdata), msg);
}

# 81 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
inline static void CC2420CsmaP__RadioBackoff__requestInitialBackoff(message_t * msg){
#line 81
  CC2420ActiveMessageP__SubBackoff__requestInitialBackoff(msg);
#line 81
}
#line 81
# 89 "/home/wtiberti/WSN/tinyos/tos/system/RandomMlcgC.nc"
static inline uint16_t RandomMlcgC__Random__rand16(void )
#line 89
{
  return (uint16_t )RandomMlcgC__Random__rand32();
}

# 52 "/home/wtiberti/WSN/tinyos/tos/interfaces/Random.nc"
inline static uint16_t CC2420CsmaP__Random__rand16(void ){
#line 52
  unsigned short __nesc_result;
#line 52

#line 52
  __nesc_result = RandomMlcgC__Random__rand16();
#line 52

#line 52
  return __nesc_result;
#line 52
}
#line 52
# 243 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline void CC2420TransmitP__RadioBackoff__setInitialBackoff(uint16_t backoffTime)
#line 243
{
  CC2420TransmitP__myInitialBackoff = backoffTime + 1;
}

# 60 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
inline static void CC2420CsmaP__SubBackoff__setInitialBackoff(uint16_t backoffTime){
#line 60
  CC2420TransmitP__RadioBackoff__setInitialBackoff(backoffTime);
#line 60
}
#line 60
# 223 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
static inline void CC2420CsmaP__SubBackoff__requestInitialBackoff(message_t *msg)
#line 223
{
  CC2420CsmaP__SubBackoff__setInitialBackoff(CC2420CsmaP__Random__rand16()
   % (0x1F * CC2420_BACKOFF_PERIOD) + CC2420_MIN_BACKOFF);

  CC2420CsmaP__RadioBackoff__requestInitialBackoff(msg);
}

# 81 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
inline static void CC2420TransmitP__RadioBackoff__requestInitialBackoff(message_t * msg){
#line 81
  CC2420CsmaP__SubBackoff__requestInitialBackoff(msg);
#line 81
}
#line 81
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420TransmitP__SpiResource__release(void ){
#line 120
  enum __nesc_unnamed4242 __nesc_result;
#line 120

#line 120
  __nesc_result = CC2420SpiP__Resource__release(/*CC2420TransmitC.Spi*/CC2420SpiC__3__CLIENT_ID);
#line 120

#line 120
  return __nesc_result;
#line 120
}
#line 120
# 803 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline error_t CC2420TransmitP__releaseSpiResource(void )
#line 803
{
  CC2420TransmitP__SpiResource__release();
  return SUCCESS;
}

# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t CC2420CsmaP__sendDone_task__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(CC2420CsmaP__sendDone_task);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 205 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
static inline void CC2420CsmaP__CC2420Transmit__sendDone(message_t *p_msg, error_t err)
#line 205
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 206
    CC2420CsmaP__sendErr = err;
#line 206
    __nesc_atomic_end(__nesc_atomic); }
  CC2420CsmaP__sendDone_task__postTask();
}

# 73 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Transmit.nc"
inline static void CC2420TransmitP__Send__sendDone(message_t * p_msg, error_t error){
#line 73
  CC2420CsmaP__CC2420Transmit__sendDone(p_msg, error);
#line 73
}
#line 73
# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420TransmitP__CSN__set(void ){
#line 40
  /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__set();
#line 40
}
#line 40
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
inline static cc2420_status_t CC2420TransmitP__SFLUSHTX__strobe(void ){
#line 53
  unsigned char __nesc_result;
#line 53

#line 53
  __nesc_result = CC2420SpiP__Strobe__strobe(CC2420_SFLUSHTX);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420TransmitP__CSN__clr(void ){
#line 41
  /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__clr();
#line 41
}
#line 41
# 454 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline void CC2420TransmitP__TXFIFO__writeDone(uint8_t *tx_buf, uint8_t tx_len, 
error_t error)
#line 455
{

  CC2420TransmitP__CSN__set();
  if (CC2420TransmitP__m_state == CC2420TransmitP__S_CANCEL) {
      /* atomic removed: atomic calls only */
#line 459
      {
        CC2420TransmitP__CSN__clr();
        CC2420TransmitP__SFLUSHTX__strobe();
        CC2420TransmitP__CSN__set();
      }
      CC2420TransmitP__releaseSpiResource();
      CC2420TransmitP__m_state = CC2420TransmitP__S_STARTED;
      CC2420TransmitP__Send__sendDone(CC2420TransmitP__m_msg, ECANCEL);
    }
  else {
#line 468
    if (!CC2420TransmitP__m_cca) {
        /* atomic removed: atomic calls only */
#line 469
        {
          CC2420TransmitP__m_state = CC2420TransmitP__S_BEGIN_TRANSMIT;
        }
        CC2420TransmitP__attemptSend();
      }
    else {
        CC2420TransmitP__releaseSpiResource();
        /* atomic removed: atomic calls only */
#line 476
        {
          CC2420TransmitP__m_state = CC2420TransmitP__S_SAMPLE_CCA;
        }

        CC2420TransmitP__RadioBackoff__requestInitialBackoff(CC2420TransmitP__m_msg);
        CC2420TransmitP__BackoffTimer__start(CC2420TransmitP__myInitialBackoff);
      }
    }
}

# 668 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static inline void CC2420ReceiveP__RXFIFO__writeDone(uint8_t *tx_buf, uint8_t tx_len, error_t error)
#line 668
{
}

# 373 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static inline void CC2420SpiP__Fifo__default__writeDone(uint8_t addr, uint8_t *tx_buf, uint8_t tx_len, error_t error)
#line 373
{
}

# 91 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
inline static void CC2420SpiP__Fifo__writeDone(uint8_t arg_0x7f7cba9baa00, uint8_t * data, uint8_t length, error_t error){
#line 91
  switch (arg_0x7f7cba9baa00) {
#line 91
    case CC2420_TXFIFO:
#line 91
      CC2420TransmitP__TXFIFO__writeDone(data, length, error);
#line 91
      break;
#line 91
    case CC2420_RXFIFO:
#line 91
      CC2420ReceiveP__RXFIFO__writeDone(data, length, error);
#line 91
      break;
#line 91
    default:
#line 91
      CC2420SpiP__Fifo__default__writeDone(arg_0x7f7cba9baa00, data, length, error);
#line 91
      break;
#line 91
    }
#line 91
}
#line 91
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
inline static cc2420_status_t CC2420TransmitP__STXONCCA__strobe(void ){
#line 53
  unsigned char __nesc_result;
#line 53

#line 53
  __nesc_result = CC2420SpiP__Strobe__strobe(CC2420_STXONCCA);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
inline static cc2420_status_t CC2420TransmitP__STXON__strobe(void ){
#line 53
  unsigned char __nesc_result;
#line 53

#line 53
  __nesc_result = CC2420SpiP__Strobe__strobe(CC2420_STXON);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
inline static cc2420_status_t CC2420TransmitP__SNOP__strobe(void ){
#line 53
  unsigned char __nesc_result;
#line 53

#line 53
  __nesc_result = CC2420SpiP__Strobe__strobe(CC2420_SNOP);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 297 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void CC2420ActiveMessageP__RadioBackoff__default__requestCongestionBackoff(am_id_t id, 
message_t *msg)
#line 298
{
}

# 88 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
inline static void CC2420ActiveMessageP__RadioBackoff__requestCongestionBackoff(am_id_t arg_0x7f7cba393700, message_t * msg){
#line 88
    CC2420ActiveMessageP__RadioBackoff__default__requestCongestionBackoff(arg_0x7f7cba393700, msg);
#line 88
}
#line 88
# 246 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void CC2420ActiveMessageP__SubBackoff__requestCongestionBackoff(message_t *msg)
#line 246
{
  CC2420ActiveMessageP__RadioBackoff__requestCongestionBackoff(__nesc_ntoh_leuint8(((cc2420_header_t * )((uint8_t *)msg + (unsigned short )& ((message_t *)0)->data - sizeof(cc2420_header_t )))->type.nxdata), msg);
}

# 88 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
inline static void CC2420CsmaP__RadioBackoff__requestCongestionBackoff(message_t * msg){
#line 88
  CC2420ActiveMessageP__SubBackoff__requestCongestionBackoff(msg);
#line 88
}
#line 88
# 251 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline void CC2420TransmitP__RadioBackoff__setCongestionBackoff(uint16_t backoffTime)
#line 251
{
  CC2420TransmitP__myCongestionBackoff = backoffTime + 1;
}

# 66 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
inline static void CC2420CsmaP__SubBackoff__setCongestionBackoff(uint16_t backoffTime){
#line 66
  CC2420TransmitP__RadioBackoff__setCongestionBackoff(backoffTime);
#line 66
}
#line 66
# 230 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
static inline void CC2420CsmaP__SubBackoff__requestCongestionBackoff(message_t *msg)
#line 230
{
  CC2420CsmaP__SubBackoff__setCongestionBackoff(CC2420CsmaP__Random__rand16()
   % (0x7 * CC2420_BACKOFF_PERIOD) + CC2420_MIN_BACKOFF);

  CC2420CsmaP__RadioBackoff__requestCongestionBackoff(msg);
}

# 88 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
inline static void CC2420TransmitP__RadioBackoff__requestCongestionBackoff(message_t * msg){
#line 88
  CC2420CsmaP__SubBackoff__requestCongestionBackoff(msg);
#line 88
}
#line 88
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline uint16_t HplAtm128Timer1P__Timer__get(void )
#line 58
{
#line 58
  return * (volatile uint16_t *)(0x2C + 0x20);
}

# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__timer_size /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__get(void ){
#line 61
  unsigned short __nesc_result;
#line 61

#line 61
  __nesc_result = HplAtm128Timer1P__Timer__get();
#line 61

#line 61
  return __nesc_result;
#line 61
}
#line 61
# 50 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128CounterC.nc"
static inline /*CounterOne16C.NCounter*/Atm128CounterC__0__timer_size /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__get(void )
{
  return /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__get();
}

# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__size_type /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__get(void ){
#line 64
  unsigned short __nesc_result;
#line 64

#line 64
  __nesc_result = /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64
# 103 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer0AsyncP.nc"
static inline Atm128_TIFR_t HplAtm128Timer0AsyncP__TimerCtrl__getInterruptFlag(void )
#line 103
{
  return * (Atm128_TIFR_t *)& * (volatile uint8_t *)(0x36 + 0x20);
}

# 53 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128TimerCtrl8.nc"
inline static Atm128_TIFR_t HplAtm128Timer1P__Timer0Ctrl__getInterruptFlag(void ){
#line 53
  union __nesc_unnamed4275 __nesc_result;
#line 53

#line 53
  __nesc_result = HplAtm128Timer0AsyncP__TimerCtrl__getInterruptFlag();
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 153 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline bool HplAtm128Timer1P__Timer__test(void )
#line 153
{
  return HplAtm128Timer1P__Timer0Ctrl__getInterruptFlag().bits.tov1;
}

# 87 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static bool /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__test(void ){
#line 87
  unsigned char __nesc_result;
#line 87

#line 87
  __nesc_result = HplAtm128Timer1P__Timer__test();
#line 87

#line 87
  return __nesc_result;
#line 87
}
#line 87
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128CounterC.nc"
static inline bool /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__isOverflowPending(void )
{
  return /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__test();
}

# 71 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static bool /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__isOverflowPending(void ){
#line 71
  unsigned char __nesc_result;
#line 71

#line 71
  __nesc_result = /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__isOverflowPending();
#line 71

#line 71
  return __nesc_result;
#line 71
}
#line 71
# 142 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline void HplAtm128Timer1P__CompareA__start(void )
#line 142
{
#line 142
  * (volatile uint8_t *)(0x37 + 0x20) |= 1 << 4;
}

# 65 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__start(void ){
#line 65
  HplAtm128Timer1P__CompareA__start();
#line 65
}
#line 65
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline void HplAtm128Timer1P__CompareA__reset(void )
#line 136
{
#line 136
  * (volatile uint8_t *)(0x36 + 0x20) = 1 << 4;
}

# 62 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__reset(void ){
#line 62
  HplAtm128Timer1P__CompareA__reset();
#line 62
}
#line 62
# 192 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline void HplAtm128Timer1P__CompareA__set(uint16_t t)
#line 192
{
#line 192
  * (volatile uint16_t *)(0x2A + 0x20) = t;
}

# 54 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__set(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__size_type t){
#line 54
  HplAtm128Timer1P__CompareA__set(t);
#line 54
}
#line 54
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Timer__timer_size /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Timer__get(void ){
#line 61
  unsigned short __nesc_result;
#line 61

#line 61
  __nesc_result = HplAtm128Timer1P__Timer__get();
#line 61

#line 61
  return __nesc_result;
#line 61
}
#line 61
# 83 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__timer_size t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__timer_size dt)
#line 83
{
  /* atomic removed: atomic calls only */






  {
    /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__timer_size now;
#line 92
    /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__timer_size elapsed;
#line 92
    /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__timer_size expires;

    ;


    now = /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Timer__get();
    elapsed = now + 3 - t0;
    if (elapsed >= dt) {
      expires = now + 3;
      }
    else {
#line 102
      expires = t0 + dt;
      }



    if (expires == 0) {
      expires = 1;
      }



    /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__set(expires - 1);
    /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__reset();
    /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__start();
  }
}

# 103 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__size_type t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__size_type dt){
#line 103
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__startAt(t0, dt);
#line 103
}
#line 103
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
inline static cc2420_status_t CC2420ControlP__TXCTRL__write(uint16_t data){
#line 63
  unsigned char __nesc_result;
#line 63

#line 63
  __nesc_result = CC2420SpiP__Reg__write(CC2420_TXCTRL, data);
#line 63

#line 63
  return __nesc_result;
#line 63
}
#line 63
# 533 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline void CC2420ControlP__writeTxctrl(void )
#line 533
{
  /* atomic removed: atomic calls only */
#line 534
  {
    CC2420ControlP__TXCTRL__write((((2 << CC2420_TXCTRL_TXMIXBUF_CUR) | (
    3 << CC2420_TXCTRL_PA_CURRENT)) | (
    1 << CC2420_TXCTRL_RESERVED)) | ((
    31 & 0x1F) << CC2420_TXCTRL_PA_LEVEL));
  }
}

# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
inline static cc2420_status_t CC2420ControlP__RXCTRL1__write(uint16_t data){
#line 63
  unsigned char __nesc_result;
#line 63

#line 63
  __nesc_result = CC2420SpiP__Reg__write(CC2420_RXCTRL1, data);
#line 63

#line 63
  return __nesc_result;
#line 63
}
#line 63
inline static cc2420_status_t CC2420ControlP__IOCFG0__write(uint16_t data){
#line 63
  unsigned char __nesc_result;
#line 63

#line 63
  __nesc_result = CC2420SpiP__Reg__write(CC2420_IOCFG0, data);
#line 63

#line 63
  return __nesc_result;
#line 63
}
#line 63
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
inline static cc2420_status_t CC2420ControlP__SXOSCON__strobe(void ){
#line 53
  unsigned char __nesc_result;
#line 53

#line 53
  __nesc_result = CC2420SpiP__Strobe__strobe(CC2420_SXOSCON);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t HplCC2420InterruptsP__CCATask__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(HplCC2420InterruptsP__CCATask);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline bool /*HplAtm128GeneralIOC.PortD.Bit6*/HplAtm128GeneralIOPinP__30__IO__get(void )
#line 54
{
#line 54
  return (* (volatile uint8_t * )48U & (1 << 6)) != 0;
}

# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static bool HplCC2420InterruptsP__CC_CCA__get(void ){
#line 43
  unsigned char __nesc_result;
#line 43

#line 43
  __nesc_result = /*HplAtm128GeneralIOC.PortD.Bit6*/HplAtm128GeneralIOPinP__30__IO__get();
#line 43

#line 43
  return __nesc_result;
#line 43
}
#line 43
# 89 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/chips/cc2420/HplCC2420InterruptsP.nc"
static inline error_t HplCC2420InterruptsP__CCA__enableRisingEdge(void )
#line 89
{
  /* atomic removed: atomic calls only */
#line 90
  HplCC2420InterruptsP__ccaWaitForState = TRUE;
  /* atomic removed: atomic calls only */
#line 91
  HplCC2420InterruptsP__ccaCheckDisabled = FALSE;
  HplCC2420InterruptsP__ccaLastState = HplCC2420InterruptsP__CC_CCA__get();
  HplCC2420InterruptsP__CCATask__postTask();
  return SUCCESS;
}

# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
inline static error_t CC2420ControlP__InterruptCCA__enableRisingEdge(void ){
#line 53
  enum __nesc_unnamed4242 __nesc_result;
#line 53

#line 53
  __nesc_result = HplCC2420InterruptsP__CCA__enableRisingEdge();
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
inline static cc2420_status_t CC2420ControlP__IOCFG1__write(uint16_t data){
#line 63
  unsigned char __nesc_result;
#line 63

#line 63
  __nesc_result = CC2420SpiP__Reg__write(CC2420_IOCFG1, data);
#line 63

#line 63
  return __nesc_result;
#line 63
}
#line 63
# 224 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline error_t CC2420ControlP__CC2420Power__startOscillator(void )
#line 224
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 225
    {
      if (CC2420ControlP__m_state != CC2420ControlP__S_VREG_STARTED) {
          {
            enum __nesc_unnamed4242 __nesc_temp = 
#line 227
            FAIL;

            {
#line 227
              __nesc_atomic_end(__nesc_atomic); 
#line 227
              return __nesc_temp;
            }
          }
        }
#line 230
      CC2420ControlP__m_state = CC2420ControlP__S_XOSC_STARTING;
      CC2420ControlP__IOCFG1__write(CC2420_SFDMUX_XOSC16M_STABLE << 
      CC2420_IOCFG1_CCAMUX);

      CC2420ControlP__InterruptCCA__enableRisingEdge();
      CC2420ControlP__SXOSCON__strobe();

      CC2420ControlP__IOCFG0__write((1 << CC2420_IOCFG0_FIFOP_POLARITY) | (
      127 << CC2420_IOCFG0_FIFOP_THR));

      CC2420ControlP__writeFsctrl();
      CC2420ControlP__writeMdmctrl0();

      CC2420ControlP__RXCTRL1__write(((((((1 << CC2420_RXCTRL1_RXBPF_LOCUR) | (
      1 << CC2420_RXCTRL1_LOW_LOWGAIN)) | (
      1 << CC2420_RXCTRL1_HIGH_HGM)) | (
      1 << CC2420_RXCTRL1_LNA_CAP_ARRAY)) | (
      1 << CC2420_RXCTRL1_RXMIX_TAIL)) | (
      1 << CC2420_RXCTRL1_RXMIX_VCM)) | (
      2 << CC2420_RXCTRL1_RXMIX_CURRENT));

      CC2420ControlP__writeTxctrl();
    }
#line 252
    __nesc_atomic_end(__nesc_atomic); }
  return SUCCESS;
}

# 71 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Power.nc"
inline static error_t CC2420CsmaP__CC2420Power__startOscillator(void ){
#line 71
  enum __nesc_unnamed4242 __nesc_result;
#line 71

#line 71
  __nesc_result = CC2420ControlP__CC2420Power__startOscillator();
#line 71

#line 71
  return __nesc_result;
#line 71
}
#line 71
# 214 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
static inline void CC2420CsmaP__Resource__granted(void )
#line 214
{
  CC2420CsmaP__CC2420Power__startOscillator();
}

# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static void CC2420ControlP__Resource__granted(void ){
#line 102
  CC2420CsmaP__Resource__granted();
#line 102
}
#line 102
# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__CSN__clr(void ){
#line 41
  /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__clr();
#line 41
}
#line 41
# 413 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline void CC2420ControlP__SpiResource__granted(void )
#line 413
{
  CC2420ControlP__CSN__clr();
  CC2420ControlP__Resource__granted();
}

# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t CC2420ControlP__syncDone__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(CC2420ControlP__syncDone);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420ControlP__SyncResource__release(void ){
#line 120
  enum __nesc_unnamed4242 __nesc_result;
#line 120

#line 120
  __nesc_result = CC2420SpiP__Resource__release(/*CC2420ControlC.SyncSpiC*/CC2420SpiC__1__CLIENT_ID);
#line 120

#line 120
  return __nesc_result;
#line 120
}
#line 120
# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__CSN__set(void ){
#line 40
  /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__set();
#line 40
}
#line 40
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
inline static cc2420_status_t CC2420ControlP__SRXON__strobe(void ){
#line 53
  unsigned char __nesc_result;
#line 53

#line 53
  __nesc_result = CC2420SpiP__Strobe__strobe(CC2420_SRXON);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
inline static cc2420_status_t CC2420ControlP__SRFOFF__strobe(void ){
#line 53
  unsigned char __nesc_result;
#line 53

#line 53
  __nesc_result = CC2420SpiP__Strobe__strobe(CC2420_SRFOFF);
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 399 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline void CC2420ControlP__SyncResource__granted(void )
#line 399
{
  CC2420ControlP__CSN__clr();
  CC2420ControlP__SRFOFF__strobe();
  CC2420ControlP__writeFsctrl();
  CC2420ControlP__writeMdmctrl0();
  CC2420ControlP__writeId();
  CC2420ControlP__CSN__set();
  CC2420ControlP__CSN__clr();
  CC2420ControlP__SRXON__strobe();
  CC2420ControlP__CSN__set();
  CC2420ControlP__SyncResource__release();
  CC2420ControlP__syncDone__postTask();
}

#line 545
static inline void CC2420ControlP__ReadRssi__default__readDone(error_t error, uint16_t data)
#line 545
{
}

# 63 "/home/wtiberti/WSN/tinyos/tos/interfaces/Read.nc"
inline static void CC2420ControlP__ReadRssi__readDone(error_t result, CC2420ControlP__ReadRssi__val_t val){
#line 63
  CC2420ControlP__ReadRssi__default__readDone(result, val);
#line 63
}
#line 63
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420ControlP__RssiResource__release(void ){
#line 120
  enum __nesc_unnamed4242 __nesc_result;
#line 120

#line 120
  __nesc_result = CC2420SpiP__Resource__release(/*CC2420ControlC.RssiResource*/CC2420SpiC__2__CLIENT_ID);
#line 120

#line 120
  return __nesc_result;
#line 120
}
#line 120
# 287 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static inline cc2420_status_t CC2420SpiP__Reg__read(uint8_t addr, uint16_t *data)
#line 287
{

  cc2420_status_t status = 0;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 291
    {
      if (CC2420SpiP__WorkingState__isIdle()) {
          {
            unsigned char __nesc_temp = 
#line 293
            status;

            {
#line 293
              __nesc_atomic_end(__nesc_atomic); 
#line 293
              return __nesc_temp;
            }
          }
        }
    }
#line 297
    __nesc_atomic_end(__nesc_atomic); }
#line 297
  status = CC2420SpiP__SpiByte__write(addr | 0x40);
  *data = (uint16_t )CC2420SpiP__SpiByte__write(0) << 8;
  *data |= CC2420SpiP__SpiByte__write(0);

  return status;
}

# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
inline static cc2420_status_t CC2420ControlP__RSSI__read(uint16_t *data){
#line 55
  unsigned char __nesc_result;
#line 55

#line 55
  __nesc_result = CC2420SpiP__Reg__read(CC2420_RSSI, data);
#line 55

#line 55
  return __nesc_result;
#line 55
}
#line 55
# 418 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline void CC2420ControlP__RssiResource__granted(void )
#line 418
{
  uint16_t data = 0;

#line 420
  CC2420ControlP__CSN__clr();
  CC2420ControlP__RSSI__read(&data);
  CC2420ControlP__CSN__set();

  CC2420ControlP__RssiResource__release();
  data += 0x7f;
  data &= 0x00ff;
  CC2420ControlP__ReadRssi__readDone(SUCCESS, data);
}

# 416 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline void CC2420TransmitP__SpiResource__granted(void )
#line 416
{
  uint8_t cur_state;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 419
    {
      cur_state = CC2420TransmitP__m_state;
    }
#line 421
    __nesc_atomic_end(__nesc_atomic); }

  switch (cur_state) {
      case CC2420TransmitP__S_LOAD: 
        CC2420TransmitP__loadTXFIFO();
      break;

      case CC2420TransmitP__S_BEGIN_TRANSMIT: 
        CC2420TransmitP__attemptSend();
      break;

      case CC2420TransmitP__S_CANCEL: 
        CC2420TransmitP__CSN__clr();
      CC2420TransmitP__SFLUSHTX__strobe();
      CC2420TransmitP__CSN__set();
      CC2420TransmitP__releaseSpiResource();
      { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 437
        {
          CC2420TransmitP__m_state = CC2420TransmitP__S_STARTED;
        }
#line 439
        __nesc_atomic_end(__nesc_atomic); }
      CC2420TransmitP__Send__sendDone(CC2420TransmitP__m_msg, ECANCEL);
      break;

      default: 
        CC2420TransmitP__releaseSpiResource();
      break;
    }
}

# 513 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static inline void CC2420ReceiveP__SpiResource__granted(void )
#line 513
{







  CC2420ReceiveP__receive();
}

# 367 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static inline void CC2420SpiP__Resource__default__granted(uint8_t id)
#line 367
{
}

# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static void CC2420SpiP__Resource__granted(uint8_t arg_0x7f7cba9bb660){
#line 102
  switch (arg_0x7f7cba9bb660) {
#line 102
    case /*CC2420ControlC.Spi*/CC2420SpiC__0__CLIENT_ID:
#line 102
      CC2420ControlP__SpiResource__granted();
#line 102
      break;
#line 102
    case /*CC2420ControlC.SyncSpiC*/CC2420SpiC__1__CLIENT_ID:
#line 102
      CC2420ControlP__SyncResource__granted();
#line 102
      break;
#line 102
    case /*CC2420ControlC.RssiResource*/CC2420SpiC__2__CLIENT_ID:
#line 102
      CC2420ControlP__RssiResource__granted();
#line 102
      break;
#line 102
    case /*CC2420TransmitC.Spi*/CC2420SpiC__3__CLIENT_ID:
#line 102
      CC2420TransmitP__SpiResource__granted();
#line 102
      break;
#line 102
    case /*CC2420ReceiveC.Spi*/CC2420SpiC__4__CLIENT_ID:
#line 102
      CC2420ReceiveP__SpiResource__granted();
#line 102
      break;
#line 102
    default:
#line 102
      CC2420SpiP__Resource__default__granted(arg_0x7f7cba9bb660);
#line 102
      break;
#line 102
    }
#line 102
}
#line 102
# 358 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static inline void CC2420SpiP__grant__runTask(void )
#line 358
{
  uint8_t holder;

#line 360
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 360
    {
      holder = CC2420SpiP__m_holder;
    }
#line 362
    __nesc_atomic_end(__nesc_atomic); }
  CC2420SpiP__Resource__granted(holder);
}

# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
inline static cc2420_status_t CC2420ControlP__FSCTRL__write(uint16_t data){
#line 63
  unsigned char __nesc_result;
#line 63

#line 63
  __nesc_result = CC2420SpiP__Reg__write(CC2420_FSCTRL, data);
#line 63

#line 63
  return __nesc_result;
#line 63
}
#line 63
inline static cc2420_status_t CC2420ControlP__MDMCTRL0__write(uint16_t data){
#line 63
  unsigned char __nesc_result;
#line 63

#line 63
  __nesc_result = CC2420SpiP__Reg__write(CC2420_MDMCTRL0, data);
#line 63

#line 63
  return __nesc_result;
#line 63
}
#line 63
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Ram.nc"
inline static cc2420_status_t CC2420ControlP__IEEEADR__write(uint8_t offset, uint8_t * data, uint8_t length){
#line 63
  unsigned char __nesc_result;
#line 63

#line 63
  __nesc_result = CC2420SpiP__Ram__write(CC2420_RAM_IEEEADR, offset, data, length);
#line 63

#line 63
  return __nesc_result;
#line 63
}
#line 63
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t CC2420CsmaP__startDone_task__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(CC2420CsmaP__startDone_task);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 218 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
static inline void CC2420CsmaP__CC2420Power__startOscillatorDone(void )
#line 218
{
  CC2420CsmaP__startDone_task__postTask();
}

# 76 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Power.nc"
inline static void CC2420ControlP__CC2420Power__startOscillatorDone(void ){
#line 76
  CC2420CsmaP__CC2420Power__startOscillatorDone();
#line 76
}
#line 76
# 105 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/chips/cc2420/HplCC2420InterruptsP.nc"
static inline error_t HplCC2420InterruptsP__CCA__disable(void )
#line 105
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 106
    HplCC2420InterruptsP__ccaCheckDisabled = TRUE;
#line 106
    __nesc_atomic_end(__nesc_atomic); }
  return SUCCESS;
}

# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
inline static error_t CC2420ControlP__InterruptCCA__disable(void ){
#line 61
  enum __nesc_unnamed4242 __nesc_result;
#line 61

#line 61
  __nesc_result = HplCC2420InterruptsP__CCA__disable();
#line 61

#line 61
  return __nesc_result;
#line 61
}
#line 61
# 441 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline void CC2420ControlP__InterruptCCA__fired(void )
#line 441
{
  CC2420ControlP__m_state = CC2420ControlP__S_XOSC_STARTED;
  CC2420ControlP__InterruptCCA__disable();
  CC2420ControlP__IOCFG1__write(0);
  CC2420ControlP__writeId();
  CC2420ControlP__CSN__set();
  CC2420ControlP__CSN__clr();
  CC2420ControlP__CC2420Power__startOscillatorDone();
}

# 68 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
inline static void HplCC2420InterruptsP__CCA__fired(void ){
#line 68
  CC2420ControlP__InterruptCCA__fired();
#line 68
}
#line 68
# 69 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/chips/cc2420/HplCC2420InterruptsP.nc"
static inline void HplCC2420InterruptsP__CCATask__runTask(void )
#line 69
{
  uint8_t CCAState;

#line 71
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 71
    {
      if (HplCC2420InterruptsP__ccaCheckDisabled) {
          {
#line 73
            __nesc_atomic_end(__nesc_atomic); 
#line 73
            return;
          }
        }
    }
#line 76
    __nesc_atomic_end(__nesc_atomic); }

  CCAState = HplCC2420InterruptsP__CC_CCA__get();
  if (HplCC2420InterruptsP__ccaLastState != HplCC2420InterruptsP__ccaWaitForState && CCAState == HplCC2420InterruptsP__ccaWaitForState) {
      HplCC2420InterruptsP__CCA__fired();
    }



  HplCC2420InterruptsP__ccaLastState = CCAState;
  HplCC2420InterruptsP__CCATask__postTask();
}

# 235 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void CC2420ActiveMessageP__CC2420Config__syncDone(error_t error)
#line 235
{
}

# 709 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static inline void CC2420ReceiveP__CC2420Config__syncDone(error_t error)
#line 709
{
}

# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Config.nc"
inline static void CC2420ControlP__CC2420Config__syncDone(error_t error){
#line 55
  CC2420ReceiveP__CC2420Config__syncDone(error);
#line 55
  CC2420ActiveMessageP__CC2420Config__syncDone(error);
#line 55
}
#line 55
# 469 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline void CC2420ControlP__syncDone__runTask(void )
#line 469
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 470
    CC2420ControlP__m_sync_busy = FALSE;
#line 470
    __nesc_atomic_end(__nesc_atomic); }
  CC2420ControlP__CC2420Config__syncDone(SUCCESS);
}

# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420ControlP__SyncResource__request(void ){
#line 88
  enum __nesc_unnamed4242 __nesc_result;
#line 88

#line 88
  __nesc_result = CC2420SpiP__Resource__request(/*CC2420ControlC.SyncSpiC*/CC2420SpiC__1__CLIENT_ID);
#line 88

#line 88
  return __nesc_result;
#line 88
}
#line 88
# 323 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline error_t CC2420ControlP__CC2420Config__sync(void )
#line 323
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 324
    {
      if (CC2420ControlP__m_sync_busy) {
          {
            enum __nesc_unnamed4242 __nesc_temp = 
#line 326
            FAIL;

            {
#line 326
              __nesc_atomic_end(__nesc_atomic); 
#line 326
              return __nesc_temp;
            }
          }
        }
#line 329
      CC2420ControlP__m_sync_busy = TRUE;
      if (CC2420ControlP__m_state == CC2420ControlP__S_XOSC_STARTED) {
          CC2420ControlP__SyncResource__request();
        }
      else 
#line 332
        {
          CC2420ControlP__syncDone__postTask();
        }
    }
#line 335
    __nesc_atomic_end(__nesc_atomic); }
  return SUCCESS;
}

#line 465
static inline void CC2420ControlP__sync__runTask(void )
#line 465
{
  CC2420ControlP__CC2420Config__sync();
}

# 248 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
static inline void CC2420TinyosNetworkP__BareSend__default__sendDone(message_t *msg, error_t error)
#line 248
{
}

# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static void CC2420TinyosNetworkP__BareSend__sendDone(message_t * msg, error_t error){
#line 100
  CC2420TinyosNetworkP__BareSend__default__sendDone(msg, error);
#line 100
}
#line 100
# 110 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
inline static void CC2420ActiveMessageP__AMSend__sendDone(am_id_t arg_0x7f7cba39bcf0, message_t * msg, error_t error){
#line 110
  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMSend__sendDone(arg_0x7f7cba39bcf0, msg, error);
#line 110
}
#line 110
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420ActiveMessageP__RadioResource__release(void ){
#line 120
  enum __nesc_unnamed4242 __nesc_result;
#line 120

#line 120
  __nesc_result = CC2420TinyosNetworkP__Resource__release(CC2420ActiveMessageC__CC2420_AM_SEND_ID);
#line 120

#line 120
  return __nesc_result;
#line 120
}
#line 120
# 212 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void CC2420ActiveMessageP__SubSend__sendDone(message_t *msg, error_t result)
#line 212
{
  CC2420ActiveMessageP__RadioResource__release();
  CC2420ActiveMessageP__AMSend__sendDone(CC2420ActiveMessageP__AMPacket__type(msg), msg, result);
}

# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static void CC2420TinyosNetworkP__ActiveSend__sendDone(message_t * msg, error_t error){
#line 100
  CC2420ActiveMessageP__SubSend__sendDone(msg, error);
#line 100
}
#line 100
# 149 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
static inline void CC2420TinyosNetworkP__SubSend__sendDone(message_t *msg, error_t error)
#line 149
{
  if (CC2420TinyosNetworkP__m_busy_client == CC2420TinyosNetworkP__CLIENT_AM) {
      CC2420TinyosNetworkP__ActiveSend__sendDone(msg, error);
    }
  else 
#line 152
    {
      CC2420TinyosNetworkP__BareSend__sendDone(msg, error);
    }
}

# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static void UniqueSendP__Send__sendDone(message_t * msg, error_t error){
#line 100
  CC2420TinyosNetworkP__SubSend__sendDone(msg, error);
#line 100
}
#line 100
# 104 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/unique/UniqueSendP.nc"
static inline void UniqueSendP__SubSend__sendDone(message_t *msg, error_t error)
#line 104
{
  UniqueSendP__State__toIdle();
  UniqueSendP__Send__sendDone(msg, error);
}

# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static void CC2420CsmaP__Send__sendDone(message_t * msg, error_t error){
#line 100
  UniqueSendP__SubSend__sendDone(msg, error);
#line 100
}
#line 100
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t CC2420CsmaP__stopDone_task__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(CC2420CsmaP__stopDone_task);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit6*/HplAtm128GeneralIOPinP__6__IO__set(void )
#line 55
{
#line 55
  * (volatile uint8_t * )59U |= 1 << 6;
}

# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__RSTN__set(void ){
#line 40
  /*HplAtm128GeneralIOC.PortA.Bit6*/HplAtm128GeneralIOPinP__6__IO__set();
#line 40
}
#line 40
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit5*/HplAtm128GeneralIOPinP__5__IO__clr(void )
#line 56
{
#line 56
  * (volatile uint8_t * )59U &= ~(1 << 5);
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__VREN__clr(void ){
#line 41
  /*HplAtm128GeneralIOC.PortA.Bit5*/HplAtm128GeneralIOPinP__5__IO__clr();
#line 41
}
#line 41
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit6*/HplAtm128GeneralIOPinP__6__IO__clr(void )
#line 56
{
#line 56
  * (volatile uint8_t * )59U &= ~(1 << 6);
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__RSTN__clr(void ){
#line 41
  /*HplAtm128GeneralIOC.PortA.Bit6*/HplAtm128GeneralIOPinP__6__IO__clr();
#line 41
}
#line 41
# 216 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline error_t CC2420ControlP__CC2420Power__stopVReg(void )
#line 216
{
  CC2420ControlP__m_state = CC2420ControlP__S_VREG_STOPPED;
  CC2420ControlP__RSTN__clr();
  CC2420ControlP__VREN__clr();
  CC2420ControlP__RSTN__set();
  return SUCCESS;
}

# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Power.nc"
inline static error_t CC2420CsmaP__CC2420Power__stopVReg(void ){
#line 63
  enum __nesc_unnamed4242 __nesc_result;
#line 63

#line 63
  __nesc_result = CC2420ControlP__CC2420Power__stopVReg();
#line 63

#line 63
  return __nesc_result;
#line 63
}
#line 63
# 52 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static __inline void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__disable(void )
#line 52
{
#line 52
  * (volatile uint8_t *)(0x39 + 0x20) &= ~(1 << 6);
}

# 51 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__disable(void ){
#line 51
  /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__disable();
#line 51
}
#line 51
# 33 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/Atm128GpioInterruptC.nc"
static inline error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Interrupt__disable(void )
#line 33
{
  /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__disable();
  return SUCCESS;
}

# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
inline static error_t CC2420ReceiveP__InterruptFIFOP__disable(void ){
#line 61
  enum __nesc_unnamed4242 __nesc_result;
#line 61

#line 61
  __nesc_result = /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Interrupt__disable();
#line 61

#line 61
  return __nesc_result;
#line 61
}
#line 61
# 171 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static inline error_t CC2420ReceiveP__StdControl__stop(void )
#line 171
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 172
    {
      CC2420ReceiveP__m_state = CC2420ReceiveP__S_STOPPED;
      CC2420ReceiveP__reset_state();
      CC2420ReceiveP__CSN__set();
      CC2420ReceiveP__InterruptFIFOP__disable();
    }
#line 177
    __nesc_atomic_end(__nesc_atomic); }
  return SUCCESS;
}

# 147 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline void HplAtm128Timer1P__Capture__stop(void )
#line 147
{
#line 147
  * (volatile uint8_t *)(0x37 + 0x20) &= ~(1 << 5);
}

# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Capture.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__stop(void ){
#line 70
  HplAtm128Timer1P__Capture__stop();
#line 70
}
#line 70
# 67 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128GpioCaptureC.nc"
static inline void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__disable(void )
#line 67
{
  /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__stop();
}

# 66 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
inline static void CC2420TransmitP__CaptureSFD__disable(void ){
#line 66
  /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__disable();
#line 66
}
#line 66
# 179 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline error_t CC2420TransmitP__StdControl__stop(void )
#line 179
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 180
    {
      CC2420TransmitP__m_state = CC2420TransmitP__S_STOPPED;
      CC2420TransmitP__BackoffTimer__stop();
      CC2420TransmitP__CaptureSFD__disable();
      CC2420TransmitP__SpiResource__release();
      CC2420TransmitP__CSN__set();
    }
#line 186
    __nesc_atomic_end(__nesc_atomic); }
  return SUCCESS;
}

# 105 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
inline static error_t CC2420CsmaP__SubControl__stop(void ){
#line 105
  enum __nesc_unnamed4242 __nesc_result;
#line 105

#line 105
  __nesc_result = CC2420TransmitP__StdControl__stop();
#line 105
  __nesc_result = ecombine(__nesc_result, CC2420ReceiveP__StdControl__stop());
#line 105

#line 105
  return __nesc_result;
#line 105
}
#line 105
# 275 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
static inline void CC2420CsmaP__shutdown(void )
#line 275
{
  CC2420CsmaP__SubControl__stop();
  CC2420CsmaP__CC2420Power__stopVReg();
  CC2420CsmaP__stopDone_task__postTask();
}

#line 244
static inline void CC2420CsmaP__sendDone_task__runTask(void )
#line 244
{
  error_t packetErr;

#line 246
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 246
    packetErr = CC2420CsmaP__sendErr;
#line 246
    __nesc_atomic_end(__nesc_atomic); }
  if (CC2420CsmaP__SplitControlState__isState(CC2420CsmaP__S_STOPPING)) {
      CC2420CsmaP__shutdown();
    }
  else {
      CC2420CsmaP__SplitControlState__forceState(CC2420CsmaP__S_STARTED);
    }

  CC2420CsmaP__Send__sendDone(CC2420CsmaP__m_msg, packetErr);
}

# 68 "BlinkToRadioC.nc"
static inline void BlinkToRadioC__AMControl__stopDone(error_t err)
#line 68
{
}

# 138 "/home/wtiberti/WSN/tinyos/tos/interfaces/SplitControl.nc"
inline static void CC2420CsmaP__SplitControl__stopDone(error_t error){
#line 138
  BlinkToRadioC__AMControl__stopDone(error);
#line 138
}
#line 138
# 265 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
static inline void CC2420CsmaP__stopDone_task__runTask(void )
#line 265
{
  CC2420CsmaP__SplitControlState__forceState(CC2420CsmaP__S_STOPPED);
  CC2420CsmaP__SplitControl__stopDone(SUCCESS);
}

# 104 "/home/wtiberti/WSN/tinyos/tos/interfaces/SplitControl.nc"
inline static error_t BlinkToRadioC__AMControl__start(void ){
#line 104
  enum __nesc_unnamed4242 __nesc_result;
#line 104

#line 104
  __nesc_result = CC2420CsmaP__SplitControl__start();
#line 104

#line 104
  return __nesc_result;
#line 104
}
#line 104
# 222 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmAsyncP.nc"
static inline uint32_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__getNow(void )
#line 222
{
  return /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Counter__get();
}

# 109 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__size_type /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__getNow(void ){
#line 109
  unsigned long __nesc_result;
#line 109

#line 109
  __nesc_result = /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__getNow();
#line 109

#line 109
  return __nesc_result;
#line 109
}
#line 109
# 96 "/home/wtiberti/WSN/tinyos/tos/lib/timer/AlarmToTimerC.nc"
static inline uint32_t /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__getNow(void )
{
#line 97
  return /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__getNow();
}

# 136 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
inline static uint32_t /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__getNow(void ){
#line 136
  unsigned long __nesc_result;
#line 136

#line 136
  __nesc_result = /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__getNow();
#line 136

#line 136
  return __nesc_result;
#line 136
}
#line 136
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__updateFromTimer__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(/*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__updateFromTimer);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 142 "/home/wtiberti/WSN/tinyos/tos/lib/timer/VirtualizeTimerImplP.nc"
static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__trace_start_timer(uint16_t num)
#line 142
{
}

#line 231
static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__startTimer(uint8_t num, uint32_t t0, uint32_t dt, bool isoneshot)
#line 231
{
  /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer_t *timer = &/*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__m_timers[num];

  timer->t0 = t0;
  timer->dt = dt;
  timer->isoneshot = isoneshot;
  timer->isrunning = TRUE;
  /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__trace_start_timer(num);
  /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__updateFromTimer__postTask();
}

static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__startPeriodic(uint8_t num, uint32_t dt)
#line 242
{
  /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__startTimer(num, /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__getNow(), dt, FALSE);
}

# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
inline static void BlinkToRadioC__Timer0__startPeriodic(uint32_t dt){
#line 64
  /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__startPeriodic(0U, dt);
#line 64
}
#line 64
# 58 "BlinkToRadioC.nc"
static inline void BlinkToRadioC__AMControl__startDone(error_t err)
#line 58
{
  if (err == SUCCESS) {
      printf("Starting timer...\r\n");
      BlinkToRadioC__Timer0__startPeriodic(TIMER_PERIOD_MILLI);
    }
  else {
      BlinkToRadioC__AMControl__start();
    }
}

# 113 "/home/wtiberti/WSN/tinyos/tos/interfaces/SplitControl.nc"
inline static void CC2420CsmaP__SplitControl__startDone(error_t error){
#line 113
  BlinkToRadioC__AMControl__startDone(error);
#line 113
}
#line 113
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420ControlP__SpiResource__release(void ){
#line 120
  enum __nesc_unnamed4242 __nesc_result;
#line 120

#line 120
  __nesc_result = CC2420SpiP__Resource__release(/*CC2420ControlC.Spi*/CC2420SpiC__0__CLIENT_ID);
#line 120

#line 120
  return __nesc_result;
#line 120
}
#line 120
# 196 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline error_t CC2420ControlP__Resource__release(void )
#line 196
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 197
    {
      CC2420ControlP__CSN__set();
      {
        enum __nesc_unnamed4242 __nesc_temp = 
#line 199
        CC2420ControlP__SpiResource__release();

        {
#line 199
          __nesc_atomic_end(__nesc_atomic); 
#line 199
          return __nesc_temp;
        }
      }
    }
#line 202
    __nesc_atomic_end(__nesc_atomic); }
}

# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420CsmaP__Resource__release(void ){
#line 120
  enum __nesc_unnamed4242 __nesc_result;
#line 120

#line 120
  __nesc_result = CC2420ControlP__Resource__release();
#line 120

#line 120
  return __nesc_result;
#line 120
}
#line 120
# 268 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline error_t CC2420ControlP__CC2420Power__rxOn(void )
#line 268
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 269
    {
      if (CC2420ControlP__m_state != CC2420ControlP__S_XOSC_STARTED) {
          {
            enum __nesc_unnamed4242 __nesc_temp = 
#line 271
            FAIL;

            {
#line 271
              __nesc_atomic_end(__nesc_atomic); 
#line 271
              return __nesc_temp;
            }
          }
        }
#line 273
      CC2420ControlP__SRXON__strobe();
    }
#line 274
    __nesc_atomic_end(__nesc_atomic); }
  return SUCCESS;
}

# 90 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Power.nc"
inline static error_t CC2420CsmaP__CC2420Power__rxOn(void ){
#line 90
  enum __nesc_unnamed4242 __nesc_result;
#line 90

#line 90
  __nesc_result = CC2420ControlP__CC2420Power__rxOn();
#line 90

#line 90
  return __nesc_result;
#line 90
}
#line 90
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static __inline void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__enable(void )
#line 51
{
#line 51
  * (volatile uint8_t *)(0x39 + 0x20) |= 1 << 6;
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__enable(void ){
#line 46
  /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__enable();
#line 46
}
#line 46
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static __inline void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__edge(bool low_to_high)
#line 56
{
  * (volatile uint8_t * )90U |= 1 << 5;

  if (low_to_high) {
    * (volatile uint8_t * )90U |= 1 << 4;
    }
  else {
#line 62
    * (volatile uint8_t * )90U &= ~(1 << 4);
    }
}

# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__edge(bool low_to_high){
#line 70
  /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__edge(low_to_high);
#line 70
}
#line 70
# 50 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static __inline void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__clear(void )
#line 50
{
#line 50
  * (volatile uint8_t *)(0x38 + 0x20) = 1 << 6;
}

# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__clear(void ){
#line 56
  /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__clear();
#line 56
}
#line 56
# 15 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/Atm128GpioInterruptC.nc"
static inline error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__enable(bool rising)
#line 15
{
  /* atomic removed: atomic calls only */
#line 16
  {
    /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__disable();
    /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__clear();
    /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__edge(rising);
    /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__enable();
  }
  return SUCCESS;
}





static inline error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Interrupt__enableFallingEdge(void )
#line 29
{
  return /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__enable(FALSE);
}

# 54 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
inline static error_t CC2420ReceiveP__InterruptFIFOP__enableFallingEdge(void ){
#line 54
  enum __nesc_unnamed4242 __nesc_result;
#line 54

#line 54
  __nesc_result = /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Interrupt__enableFallingEdge();
#line 54

#line 54
  return __nesc_result;
#line 54
}
#line 54
# 157 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static inline error_t CC2420ReceiveP__StdControl__start(void )
#line 157
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 158
    {
      CC2420ReceiveP__reset_state();
      CC2420ReceiveP__m_state = CC2420ReceiveP__S_STARTED;
      CC2420ReceiveP__receivingPacket = FALSE;




      CC2420ReceiveP__InterruptFIFOP__enableFallingEdge();
    }
#line 167
    __nesc_atomic_end(__nesc_atomic); }
  return SUCCESS;
}

# 59 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128GpioCaptureC.nc"
static inline error_t /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__captureRisingEdge(void )
#line 59
{
  return /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__enableCapture(TRUE);
}

# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
inline static error_t CC2420TransmitP__CaptureSFD__captureRisingEdge(void ){
#line 53
  enum __nesc_unnamed4242 __nesc_result;
#line 53

#line 53
  __nesc_result = /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__captureRisingEdge();
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 168 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline error_t CC2420TransmitP__StdControl__start(void )
#line 168
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 169
    {
      CC2420TransmitP__CaptureSFD__captureRisingEdge();
      CC2420TransmitP__m_state = CC2420TransmitP__S_STARTED;
      CC2420TransmitP__m_receiving = FALSE;
      CC2420TransmitP__abortSpiRelease = FALSE;
      CC2420TransmitP__m_tx_power = 0;
    }
#line 175
    __nesc_atomic_end(__nesc_atomic); }
  return SUCCESS;
}

# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
inline static error_t CC2420CsmaP__SubControl__start(void ){
#line 95
  enum __nesc_unnamed4242 __nesc_result;
#line 95

#line 95
  __nesc_result = CC2420TransmitP__StdControl__start();
#line 95
  __nesc_result = ecombine(__nesc_result, CC2420ReceiveP__StdControl__start());
#line 95

#line 95
  return __nesc_result;
#line 95
}
#line 95
# 257 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
static inline void CC2420CsmaP__startDone_task__runTask(void )
#line 257
{
  CC2420CsmaP__SubControl__start();
  CC2420CsmaP__CC2420Power__rxOn();
  CC2420CsmaP__Resource__release();
  CC2420CsmaP__SplitControlState__forceState(CC2420CsmaP__S_STARTED);
  CC2420CsmaP__SplitControl__startDone(SUCCESS);
}

# 135 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline void HplAtm128Timer1P__Capture__reset(void )
#line 135
{
#line 135
  * (volatile uint8_t *)(0x36 + 0x20) = 1 << 5;
}

# 64 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Capture.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__reset(void ){
#line 64
  HplAtm128Timer1P__Capture__reset();
#line 64
}
#line 64
# 131 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline void HplAtm128Timer1P__Capture__setEdge(bool up)
#line 131
{
#line 131
  if (up) {
#line 131
    * (volatile uint8_t *)(0x2E + 0x20) |= 1 << 6;
    }
  else {
#line 131
    * (volatile uint8_t *)(0x2E + 0x20) &= ~(1 << 6);
    }
}

# 88 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Capture.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__setEdge(bool up){
#line 88
  HplAtm128Timer1P__Capture__setEdge(up);
#line 88
}
#line 88
# 141 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline void HplAtm128Timer1P__Capture__start(void )
#line 141
{
#line 141
  * (volatile uint8_t *)(0x37 + 0x20) |= 1 << 5;
}

# 67 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Capture.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__start(void ){
#line 67
  HplAtm128Timer1P__Capture__start();
#line 67
}
#line 67
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128TimerCtrl8.nc"
inline static Atm128_TIFR_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerCtrl__getInterruptFlag(void ){
#line 53
  union __nesc_unnamed4275 __nesc_result;
#line 53

#line 53
  __nesc_result = HplAtm128Timer0AsyncP__TimerCtrl__getInterruptFlag();
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 45 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
inline static error_t CC2420CsmaP__SplitControlState__requestState(uint8_t reqState){
#line 45
  enum __nesc_unnamed4242 __nesc_result;
#line 45

#line 45
  __nesc_result = StateImplP__State__requestState(1U, reqState);
#line 45

#line 45
  return __nesc_result;
#line 45
}
#line 45
# 66 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void CC2420ControlP__StartupTimer__start(CC2420ControlP__StartupTimer__size_type dt){
#line 66
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__start(dt);
#line 66
}
#line 66
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit5*/HplAtm128GeneralIOPinP__5__IO__set(void )
#line 55
{
#line 55
  * (volatile uint8_t * )59U |= 1 << 5;
}

# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__VREN__set(void ){
#line 40
  /*HplAtm128GeneralIOC.PortA.Bit5*/HplAtm128GeneralIOPinP__5__IO__set();
#line 40
}
#line 40
# 204 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline error_t CC2420ControlP__CC2420Power__startVReg(void )
#line 204
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 205
    {
      if (CC2420ControlP__m_state != CC2420ControlP__S_VREG_STOPPED) {
          {
            enum __nesc_unnamed4242 __nesc_temp = 
#line 207
            FAIL;

            {
#line 207
              __nesc_atomic_end(__nesc_atomic); 
#line 207
              return __nesc_temp;
            }
          }
        }
#line 209
      CC2420ControlP__m_state = CC2420ControlP__S_VREG_STARTING;
    }
#line 210
    __nesc_atomic_end(__nesc_atomic); }
  CC2420ControlP__VREN__set();
  CC2420ControlP__StartupTimer__start(CC2420_TIME_VREN);
  return SUCCESS;
}

# 51 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Power.nc"
inline static error_t CC2420CsmaP__CC2420Power__startVReg(void ){
#line 51
  enum __nesc_unnamed4242 __nesc_result;
#line 51

#line 51
  __nesc_result = CC2420ControlP__CC2420Power__startVReg();
#line 51

#line 51
  return __nesc_result;
#line 51
}
#line 51
# 103 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__startAt(/*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__size_type t0, /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__size_type dt){
#line 103
  /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__startAt(t0, dt);
#line 103
}
#line 103
# 58 "/home/wtiberti/WSN/tinyos/tos/lib/timer/AlarmToTimerC.nc"
static inline void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__start(uint32_t t0, uint32_t dt, bool oneshot)
{
  /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__m_dt = dt;
  /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__m_oneshot = oneshot;
  /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__startAt(t0, dt);
}

#line 93
static inline void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__startOneShotAt(uint32_t t0, uint32_t dt)
{
#line 94
  /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__start(t0, dt, TRUE);
}

# 129 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
inline static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__startOneShotAt(uint32_t t0, uint32_t dt){
#line 129
  /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__startOneShotAt(t0, dt);
#line 129
}
#line 129
# 204 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmAsyncP.nc"
static inline void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__stop(void )
#line 204
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 205
    /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__set = FALSE;
#line 205
    __nesc_atomic_end(__nesc_atomic); }
}

# 73 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__stop(void ){
#line 73
  /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__stop();
#line 73
}
#line 73
# 71 "/home/wtiberti/WSN/tinyos/tos/lib/timer/AlarmToTimerC.nc"
static inline void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__stop(void )
{
#line 72
  /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__stop();
}

# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
inline static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__stop(void ){
#line 78
  /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__stop();
#line 78
}
#line 78
# 184 "/home/wtiberti/WSN/tinyos/tos/lib/timer/VirtualizeTimerImplP.nc"
static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__updateFromTimer__runTask(void )
#line 184
{







  uint32_t now = /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__getNow();
  int32_t min_remaining = (1UL << 31) - 1;
  bool min_remaining_isset = FALSE;
  uint16_t num;

  /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__stop();

  for (num = 0; num < /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__NUM_TIMERS; num++) {
      /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer_t *timer = &/*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__m_timers[num];

      if (timer->isrunning) {
          uint32_t elapsed = now - timer->t0;
          int32_t remaining = timer->dt - elapsed;

          if (remaining < min_remaining) {
              min_remaining = remaining;
              min_remaining_isset = TRUE;
            }
        }
    }

  if (min_remaining_isset) {
      if (min_remaining <= 0) {
        /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__fireTimers(now);
        }
      else {
#line 217
        /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__startOneShotAt(now, min_remaining);
        }
    }
}

#line 143
static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__trace_timer_fired(uint16_t num)
#line 143
{
}

# 60 "/home/wtiberti/WSN/tinyos/tos/platforms/mica/PlatformP.nc"
static inline uint32_t PlatformP__Platform__usecsRaw(void )
#line 60
{
#line 60
  return 0;
}

# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Platform.nc"
inline static uint32_t /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Platform__usecsRaw(void ){
#line 78
  unsigned long __nesc_result;
#line 78

#line 78
  __nesc_result = PlatformP__Platform__usecsRaw();
#line 78

#line 78
  return __nesc_result;
#line 78
}
#line 78
# 198 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void CC2420ActiveMessageP__Packet__setPayloadLength(message_t *msg, uint8_t len)
#line 198
{
  __nesc_hton_leuint8(CC2420ActiveMessageP__CC2420PacketBody__getHeader(msg)->length.nxdata, len + CC2420_SIZE);
}

# 94 "/home/wtiberti/WSN/tinyos/tos/interfaces/Packet.nc"
inline static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Packet__setPayloadLength(message_t * msg, uint8_t len){
#line 94
  CC2420ActiveMessageP__Packet__setPayloadLength(msg, len);
#line 94
}
#line 94
# 105 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
static inline error_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__send(uint8_t clientId, message_t *msg, 
uint8_t len)
#line 106
{
  if (clientId >= 1) {
      return FAIL;
    }
  if (/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue[clientId].msg != (void *)0) {
      return EBUSY;
    }
  ;

  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue[clientId].msg = msg;
  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Packet__setPayloadLength(msg, len);

  if (/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current >= 1) {
      error_t err;
      am_id_t amId = /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMPacket__type(msg);
      am_addr_t dest = /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMPacket__destination(msg);

      ;
      /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current = clientId;

      err = /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMSend__send(amId, dest, msg, len);
      if (err != SUCCESS) {
          ;
          /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current = 1;
          /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue[clientId].msg = (void *)0;
        }
      return err;
    }
  else {
      ;
    }
  return SUCCESS;
}

# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static error_t /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__Send__send(message_t * msg, uint8_t len){
#line 75
  enum __nesc_unnamed4242 __nesc_result;
#line 75

#line 75
  __nesc_result = /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__send(0U, msg, len);
#line 75

#line 75
  return __nesc_result;
#line 75
}
#line 75
# 169 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void CC2420ActiveMessageP__AMPacket__setType(message_t *amsg, am_id_t type)
#line 169
{
  cc2420_header_t *header = CC2420ActiveMessageP__CC2420PacketBody__getHeader(amsg);

#line 171
  __nesc_hton_leuint8(header->type.nxdata, type);
}

# 162 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMPacket.nc"
inline static void /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMPacket__setType(message_t * amsg, am_id_t t){
#line 162
  CC2420ActiveMessageP__AMPacket__setType(amsg, t);
#line 162
}
#line 162
# 149 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void CC2420ActiveMessageP__AMPacket__setDestination(message_t *amsg, am_addr_t addr)
#line 149
{
  cc2420_header_t *header = CC2420ActiveMessageP__CC2420PacketBody__getHeader(amsg);

#line 151
  __nesc_hton_leuint16(header->dest.nxdata, addr);
}

# 103 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMPacket.nc"
inline static void /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMPacket__setDestination(message_t * amsg, am_addr_t addr){
#line 103
  CC2420ActiveMessageP__AMPacket__setDestination(amsg, addr);
#line 103
}
#line 103
# 53 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueEntryP.nc"
static inline error_t /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMSend__send(am_addr_t dest, 
message_t *msg, 
uint8_t len)
#line 55
{
  /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMPacket__setDestination(msg, dest);
  /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMPacket__setType(msg, 6);
  return /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__Send__send(msg, len);
}

# 80 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
inline static error_t BlinkToRadioC__AMSend__send(am_addr_t addr, message_t * msg, uint8_t len){
#line 80
  enum __nesc_unnamed4242 __nesc_result;
#line 80

#line 80
  __nesc_result = /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__AMSend__send(addr, msg, len);
#line 80

#line 80
  return __nesc_result;
#line 80
}
#line 80
# 193 "../TAKSM.nc"
static inline void TAKSM__symmetric_encrypt(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k)
{



  int i;

#line 199
  for (i = 0; i < size; ++i) {
      out[i] = in[i] ^ k[i % 16];
    }
}

#line 145
static inline uint8_t *TAKSM__tc_getY(uint8_t *data)
#line 145
{
#line 145
  return data + 16 * 2 / 2;
}

#line 27
static inline uint32_t TAKSM__getSeed(void )
{

  return 0x11223344;
}

# 56 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer3P.nc"
static inline uint16_t HplAtm128Timer3P__Timer__get(void )
#line 56
{
#line 56
  return * (volatile uint16_t *)0x88;
}

# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__timer_size /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__get(void ){
#line 61
  unsigned short __nesc_result;
#line 61

#line 61
  __nesc_result = HplAtm128Timer3P__Timer__get();
#line 61

#line 61
  return __nesc_result;
#line 61
}
#line 61
# 50 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128CounterC.nc"
static inline /*CounterThree16C.NCounter*/Atm128CounterC__1__timer_size /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__get(void )
{
  return /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__get();
}

# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__size_type /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__get(void ){
#line 64
  unsigned short __nesc_result;
#line 64

#line 64
  __nesc_result = /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64
# 115 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer3P.nc"
static inline Atm128_ETIFR_t HplAtm128Timer3P__TimerCtrl__getInterruptFlag(void )
#line 115
{
  return * (Atm128_ETIFR_t *)& * (volatile uint8_t *)0x7C;
}

#line 148
static inline bool HplAtm128Timer3P__Timer__test(void )
#line 148
{
  return HplAtm128Timer3P__TimerCtrl__getInterruptFlag().bits.tov3;
}

# 87 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static bool /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__test(void ){
#line 87
  unsigned char __nesc_result;
#line 87

#line 87
  __nesc_result = HplAtm128Timer3P__Timer__test();
#line 87

#line 87
  return __nesc_result;
#line 87
}
#line 87
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128CounterC.nc"
static inline bool /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__isOverflowPending(void )
{
  return /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__test();
}

# 71 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static bool /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__isOverflowPending(void ){
#line 71
  unsigned char __nesc_result;
#line 71

#line 71
  __nesc_result = /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__isOverflowPending();
#line 71

#line 71
  return __nesc_result;
#line 71
}
#line 71
# 80 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
static inline /*CounterMicro32C.Transform32*/TransformCounterC__1__to_size_type /*CounterMicro32C.Transform32*/TransformCounterC__1__Counter__get(void )
{
  /*CounterMicro32C.Transform32*/TransformCounterC__1__to_size_type rv = 0;

#line 83
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      /*CounterMicro32C.Transform32*/TransformCounterC__1__upper_count_type high = /*CounterMicro32C.Transform32*/TransformCounterC__1__m_upper;
      /*CounterMicro32C.Transform32*/TransformCounterC__1__from_size_type low = /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__get();

#line 87
      if (/*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__isOverflowPending()) 
        {






          high++;
          low = /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__get();
        }
      {
        /*CounterMicro32C.Transform32*/TransformCounterC__1__to_size_type high_to = high;
        /*CounterMicro32C.Transform32*/TransformCounterC__1__to_size_type low_to = low >> /*CounterMicro32C.Transform32*/TransformCounterC__1__LOW_SHIFT_RIGHT;

#line 101
        rv = (high_to << /*CounterMicro32C.Transform32*/TransformCounterC__1__HIGH_SHIFT_LEFT) | low_to;
      }
    }
#line 103
    __nesc_atomic_end(__nesc_atomic); }
  return rv;
}

# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__size_type /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__get(void ){
#line 64
  unsigned long __nesc_result;
#line 64

#line 64
  __nesc_result = /*CounterMicro32C.Transform32*/TransformCounterC__1__Counter__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64
# 53 "/home/wtiberti/WSN/tinyos/tos/lib/timer/CounterToLocalTimeC.nc"
static inline uint32_t /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__LocalTime__get(void )
{
  return /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__get();
}

# 61 "/home/wtiberti/WSN/tinyos/tos/lib/timer/LocalTime.nc"
inline static uint32_t TAKSM__LocalTime__get(void ){
#line 61
  unsigned long __nesc_result;
#line 61

#line 61
  __nesc_result = /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__LocalTime__get();
#line 61

#line 61
  return __nesc_result;
#line 61
}
#line 61
# 33 "../TAKSM.nc"
static inline void TAKSM__getNonce(uint8_t *out)
{
  int i;
#line 35
  int j;
  uint8_t p[4];
  uint8_t q[4];
  uint32_t *p32 = (uint32_t *)p;
  uint32_t *q32 = (uint32_t *)q;
  uint32_t n;
  uint32_t s;
  uint32_t x;

  srand(TAKSM__LocalTime__get());
  for (i = 0; i < 4; ++i) {
      p[i] = rand() & 0xFF;
      q[i] = rand() & 0xFF;
    }
  while (*p32 % 4 != 3) *p32 = *p32 + 1;
  while (*q32 % 4 != 3) *q32 = *q32 + 1;
  n = *p32 * *q32;
  s = TAKSM__getSeed() % n;
  x = s * s % n;

  for (i = 0; i < 16 * 2 / 2; ++i) {
      uint8_t z = 0;

#line 57
      for (j = 0; j < 8; ++j) {
          x = x * x % n;
          z |= x & 1;
          z <<= 1;
        }
      out[i] = TAKSM__tc_getY(out)[i] = z;
    }
}

#line 104
static inline int TAKSM__TAKS__Encrypt_pw(uint8_t *out_ciphertext, 
uint8_t *plaintext, size_t size, 
uint8_t *out_mac, uint8_t *out_kri, uint8_t *src_LKC, 
uint8_t *src_TKC, uint8_t *dst_TKC)
{
  uint8_t ss[16];
  uint8_t nonce[16 * 2];
  uint8_t alpha_LKC[16 * 2];

  TAKSM__getNonce(nonce);

  TAKSM__elementwise_mult(alpha_LKC, nonce, src_LKC);

  TAKSM__vector_mult(ss, alpha_LKC, dst_TKC);


  TAKSM__elementwise_mult(out_kri, nonce, src_TKC);
  TAKSM__symmetric_encrypt(out_ciphertext, plaintext, size, ss);
  TAKSM__authentication_tag(out_mac, out_ciphertext, size, ss);
  return 0;
}

# 7 "../TAKS.nc"
inline static int BlinkToRadioC__TAKS__Encrypt_pw(uint8_t *out_ciphertext, uint8_t *plaintext, size_t size, uint8_t *out_mac, uint8_t *out_kri, uint8_t *src_LKC, uint8_t *src_TKC, uint8_t *dst_TKC){
#line 7
  int __nesc_result;
#line 7

#line 7
  __nesc_result = TAKSM__TAKS__Encrypt_pw(out_ciphertext, plaintext, size, out_mac, out_kri, src_LKC, src_TKC, dst_TKC);
#line 7

#line 7
  return __nesc_result;
#line 7
}
#line 7
# 125 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
inline static void * CC2420ActiveMessageP__SubSend__getPayload(message_t * msg, uint8_t len){
#line 125
  void *__nesc_result;
#line 125

#line 125
  __nesc_result = CC2420TinyosNetworkP__ActiveSend__getPayload(msg, len);
#line 125

#line 125
  return __nesc_result;
#line 125
}
#line 125
# 206 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static inline void *CC2420ActiveMessageP__Packet__getPayload(message_t *msg, uint8_t len)
#line 206
{
  return CC2420ActiveMessageP__SubSend__getPayload(msg, len);
}

# 126 "/home/wtiberti/WSN/tinyos/tos/interfaces/Packet.nc"
inline static void * BlinkToRadioC__Packet__getPayload(message_t * msg, uint8_t len){
#line 126
  void *__nesc_result;
#line 126

#line 126
  __nesc_result = CC2420ActiveMessageP__Packet__getPayload(msg, len);
#line 126

#line 126
  return __nesc_result;
#line 126
}
#line 126
# 71 "BlinkToRadioC.nc"
static inline void BlinkToRadioC__Timer0__fired(void )
#line 71
{
  BlinkToRadioMsg temp;
  int i;

#line 74
  BlinkToRadioC__counter++;
  if (!BlinkToRadioC__busy) {
      BlinkToRadioMsg *btrpkt = (BlinkToRadioMsg *)BlinkToRadioC__Packet__getPayload(&BlinkToRadioC__pkt, sizeof(BlinkToRadioMsg ));

#line 77
      if (btrpkt == (void *)0) {
          BlinkToRadioC__Leds__led0On();
          return;
        }

      temp.payload[0] = BlinkToRadioC__counter;
      memcpy(&temp.payload[1], "TAKS test 1234\0", 15);

      BlinkToRadioC__TAKS__Encrypt_pw(btrpkt->payload, temp.payload, 16, btrpkt->mac, btrpkt->kri, BlinkToRadioC__LKC, BlinkToRadioC__sTKC, BlinkToRadioC__dTKC);

      if (BlinkToRadioC__AMSend__send(AM_BROADCAST_ADDR, &BlinkToRadioC__pkt, sizeof(BlinkToRadioMsg )) == SUCCESS) {
          BlinkToRadioC__busy = TRUE;
        }
      else {
          printf("Cannot send\r\n");
          BlinkToRadioC__Leds__led0On();
        }
    }
}

# 283 "/home/wtiberti/WSN/tinyos/tos/lib/timer/VirtualizeTimerImplP.nc"
static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__default__fired(uint8_t num)
#line 283
{
}

# 83 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
inline static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__fired(uint8_t arg_0x7f7cbaececa0){
#line 83
  switch (arg_0x7f7cbaececa0) {
#line 83
    case 0U:
#line 83
      BlinkToRadioC__Timer0__fired();
#line 83
      break;
#line 83
    default:
#line 83
      /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__default__fired(arg_0x7f7cbaececa0);
#line 83
      break;
#line 83
    }
#line 83
}
#line 83
# 146 "/home/wtiberti/WSN/tinyos/tos/lib/timer/VirtualizeTimerImplP.nc"
static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__trace_timer_end(uint16_t num, uint32_t delta)
#line 146
{
  if (delta > /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__m_timers[num].fired_max_us) {
    /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__m_timers[num].fired_max_us = delta;
    }
}

# 144 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer0AsyncP.nc"
static inline void HplAtm128Timer0AsyncP__Compare__set(uint8_t t)
#line 144
{
  * (volatile uint8_t *)(0x31 + 0x20) = t;
}

# 54 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__set(/*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__size_type t){
#line 54
  HplAtm128Timer0AsyncP__Compare__set(t);
#line 54
}
#line 54
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer0AsyncP.nc"
static inline uint8_t HplAtm128Timer0AsyncP__Timer__get(void )
#line 59
{
#line 59
  return * (volatile uint8_t *)(0x32 + 0x20);
}

# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__timer_size /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__get(void ){
#line 61
  unsigned char __nesc_result;
#line 61

#line 61
  __nesc_result = HplAtm128Timer0AsyncP__Timer__get();
#line 61

#line 61
  return __nesc_result;
#line 61
}
#line 61
# 215 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer0AsyncP.nc"
static inline int HplAtm128Timer0AsyncP__TimerAsync__compareBusy(void )
#line 215
{
  return (* (volatile uint8_t *)(0x30 + 0x20) & (1 << 1)) != 0;
}

# 44 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128TimerAsync.nc"
inline static int /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerAsync__compareBusy(void ){
#line 44
  int __nesc_result;
#line 44

#line 44
  __nesc_result = HplAtm128Timer0AsyncP__TimerAsync__compareBusy();
#line 44

#line 44
  return __nesc_result;
#line 44
}
#line 44
# 74 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmAsyncP.nc"
static inline void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__setOcr0(uint8_t n)
#line 74
{
  while (/*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerAsync__compareBusy()) 
    ;
  if (n == /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__get()) {
    n++;
    }


  if (/*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__base + n + 1 < /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__base) {
    n = -/*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__base - 1;
    }
#line 84
  /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__set(n);
}

# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__fired__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(/*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__fired);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 81 "/home/wtiberti/WSN/tinyos/tos/lib/timer/AlarmToTimerC.nc"
static inline void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__fired(void )
{
#line 82
  /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__fired__postTask();
}

# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__fired(void ){
#line 78
  /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__fired();
#line 78
}
#line 78
# 227 "/home/wtiberti/WSN/tinyos/tos/lib/timer/VirtualizeTimerImplP.nc"
static inline void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__fired(void )
#line 227
{
  /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__fireTimers(/*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__getNow());
}

# 83 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
inline static void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__fired(void ){
#line 83
  /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__TimerFrom__fired();
#line 83
}
#line 83
# 226 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmAsyncP.nc"
static inline uint32_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__getAlarm(void )
#line 226
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 227
    {
      unsigned long __nesc_temp = 
#line 227
      /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__t0 + /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__dt;

      {
#line 227
        __nesc_atomic_end(__nesc_atomic); 
#line 227
        return __nesc_temp;
      }
    }
#line 229
    __nesc_atomic_end(__nesc_atomic); }
}

# 116 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__size_type /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__getAlarm(void ){
#line 116
  unsigned long __nesc_result;
#line 116

#line 116
  __nesc_result = /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__getAlarm();
#line 116

#line 116
  return __nesc_result;
#line 116
}
#line 116
# 74 "/home/wtiberti/WSN/tinyos/tos/lib/timer/AlarmToTimerC.nc"
static inline void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__fired__runTask(void )
{
  if (/*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__m_oneshot == FALSE) {
    /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__start(/*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__getAlarm(), /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__m_dt, FALSE);
    }
#line 78
  /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Timer__fired();
}

# 131 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer0AsyncP.nc"
static inline void HplAtm128Timer0AsyncP__Compare__start(void )
#line 131
{
#line 131
  * (volatile uint8_t *)(0x37 + 0x20) |= 1 << 1;
}

# 65 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__start(void ){
#line 65
  HplAtm128Timer0AsyncP__Compare__start();
#line 65
}
#line 65
# 85 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer0AsyncP.nc"
static inline void HplAtm128Timer0AsyncP__TimerCtrl__setControl(Atm128TimerControl_t x)
#line 85
{
  * (volatile uint8_t *)(0x33 + 0x20) = x.flat;
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128TimerCtrl8.nc"
inline static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerCtrl__setControl(Atm128TimerControl_t control){
#line 46
  HplAtm128Timer0AsyncP__TimerCtrl__setControl(control);
#line 46
}
#line 46
# 207 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer0AsyncP.nc"
static inline void HplAtm128Timer0AsyncP__TimerAsync__setTimer0Asynchronous(void )
#line 207
{
  * (volatile uint8_t *)(0x30 + 0x20) |= 1 << 3;
}

# 32 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128TimerAsync.nc"
inline static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerAsync__setTimer0Asynchronous(void ){
#line 32
  HplAtm128Timer0AsyncP__TimerAsync__setTimer0Asynchronous();
#line 32
}
#line 32
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmAsyncP.nc"
static inline error_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Init__init(void )
#line 54
{
  /* atomic removed: atomic calls only */
  {
    Atm128TimerControl_t x;

    /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerAsync__setTimer0Asynchronous();
    x.flat = 0;
    x.bits.cs = 3;
    x.bits.wgm1 = 1;
    /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerCtrl__setControl(x);
    /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__set(/*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__MAXT);
    /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__start();
  }
  /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__setInterrupt();
  return SUCCESS;
}

# 48 "/home/wtiberti/WSN/tinyos/tos/interfaces/LocalIeeeEui64.nc"
inline static ieee_eui64_t CC2420ControlP__LocalIeeeEui64__getId(void ){
#line 48
  struct ieee_eui64 __nesc_result;
#line 48

#line 48
  __nesc_result = LocalIeeeEui64C__LocalIeeeEui64__getId();
#line 48

#line 48
  return __nesc_result;
#line 48
}
#line 48
# 94 "/home/wtiberti/WSN/tinyos/tos/system/ActiveMessageAddressC.nc"
static inline am_group_t ActiveMessageAddressC__ActiveMessageAddress__amGroup(void )
#line 94
{
  am_group_t myGroup;

  /* atomic removed: atomic calls only */
#line 96
  myGroup = ActiveMessageAddressC__group;
  return myGroup;
}

# 55 "/home/wtiberti/WSN/tinyos/tos/interfaces/ActiveMessageAddress.nc"
inline static am_group_t CC2420ControlP__ActiveMessageAddress__amGroup(void ){
#line 55
  unsigned char __nesc_result;
#line 55

#line 55
  __nesc_result = ActiveMessageAddressC__ActiveMessageAddress__amGroup();
#line 55

#line 55
  return __nesc_result;
#line 55
}
#line 55
#line 50
inline static am_addr_t CC2420ControlP__ActiveMessageAddress__amAddress(void ){
#line 50
  unsigned short __nesc_result;
#line 50

#line 50
  __nesc_result = ActiveMessageAddressC__ActiveMessageAddress__amAddress();
#line 50

#line 50
  return __nesc_result;
#line 50
}
#line 50
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit5*/HplAtm128GeneralIOPinP__5__IO__makeOutput(void )
#line 61
{
#line 61
  * (volatile uint8_t * )58U |= 1 << 5;
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__VREN__makeOutput(void ){
#line 46
  /*HplAtm128GeneralIOC.PortA.Bit5*/HplAtm128GeneralIOPinP__5__IO__makeOutput();
#line 46
}
#line 46
# 61 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortA.Bit6*/HplAtm128GeneralIOPinP__6__IO__makeOutput(void )
#line 61
{
#line 61
  * (volatile uint8_t * )58U |= 1 << 6;
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__RSTN__makeOutput(void ){
#line 46
  /*HplAtm128GeneralIOC.PortA.Bit6*/HplAtm128GeneralIOPinP__6__IO__makeOutput();
#line 46
}
#line 46
inline static void CC2420ControlP__CSN__makeOutput(void ){
#line 46
  /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__makeOutput();
#line 46
}
#line 46
# 129 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline error_t CC2420ControlP__Init__init(void )
#line 129
{
  int i;
#line 130
  int t;

#line 131
  CC2420ControlP__CSN__makeOutput();
  CC2420ControlP__RSTN__makeOutput();
  CC2420ControlP__VREN__makeOutput();

  CC2420ControlP__m_short_addr = CC2420ControlP__ActiveMessageAddress__amAddress();
  CC2420ControlP__m_ext_addr = CC2420ControlP__LocalIeeeEui64__getId();
  CC2420ControlP__m_pan = CC2420ControlP__ActiveMessageAddress__amGroup();
  CC2420ControlP__m_tx_power = 31;
  CC2420ControlP__m_channel = 26;

  CC2420ControlP__m_ext_addr = CC2420ControlP__LocalIeeeEui64__getId();
  for (i = 0; i < 4; i++) {
      t = CC2420ControlP__m_ext_addr.data[i];
      CC2420ControlP__m_ext_addr.data[i] = CC2420ControlP__m_ext_addr.data[7 - i];
      CC2420ControlP__m_ext_addr.data[7 - i] = t;
    }





  CC2420ControlP__addressRecognition = TRUE;





  CC2420ControlP__hwAddressRecognition = FALSE;






  CC2420ControlP__autoAckEnabled = TRUE;






  CC2420ControlP__hwAutoAckDefault = FALSE;



  return SUCCESS;
}

# 81 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
static inline error_t StateImplP__Init__init(void )
#line 81
{
  int i;

#line 83
  for (i = 0; i < 4U; i++) {
      StateImplP__state[i] = StateImplP__S_IDLE;
    }
  return SUCCESS;
}

# 55 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
static inline error_t /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__Init__init(void )
#line 55
{
  memset(/*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__resQ, /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__NO_ENTRY, sizeof /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__resQ);
  return SUCCESS;
}

# 22 "/home/wtiberti/WSN/tinyos/tos/system/NoInitC.nc"
static inline error_t NoInitC__Init__init(void )
#line 22
{
  return SUCCESS;
}

# 59 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortD.Bit4*/HplAtm128GeneralIOPinP__28__IO__makeInput(void )
#line 59
{
#line 59
  * (volatile uint8_t * )49U &= ~(1 << 4);
}

# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420TransmitP__SFD__makeInput(void ){
#line 44
  /*HplAtm128GeneralIOC.PortD.Bit4*/HplAtm128GeneralIOPinP__28__IO__makeInput();
#line 44
}
#line 44


inline static void CC2420TransmitP__CSN__makeOutput(void ){
#line 46
  /*HplAtm128GeneralIOC.PortB.Bit0*/HplAtm128GeneralIOPinP__8__IO__makeOutput();
#line 46
}
#line 46
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline void /*HplAtm128GeneralIOC.PortD.Bit6*/HplAtm128GeneralIOPinP__30__IO__makeInput(void )
#line 59
{
#line 59
  * (volatile uint8_t * )49U &= ~(1 << 6);
}

# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420TransmitP__CCA__makeInput(void ){
#line 44
  /*HplAtm128GeneralIOC.PortD.Bit6*/HplAtm128GeneralIOPinP__30__IO__makeInput();
#line 44
}
#line 44
# 160 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline error_t CC2420TransmitP__Init__init(void )
#line 160
{
  CC2420TransmitP__CCA__makeInput();
  CC2420TransmitP__CSN__makeOutput();
  CC2420TransmitP__SFD__makeInput();
  return SUCCESS;
}

# 151 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static inline error_t CC2420ReceiveP__Init__init(void )
#line 151
{
  CC2420ReceiveP__m_p_rx_buf = &CC2420ReceiveP__m_rx_buf;
  return SUCCESS;
}

# 55 "/home/wtiberti/WSN/tinyos/tos/system/RandomMlcgC.nc"
static inline error_t RandomMlcgC__Init__init(void )
#line 55
{
  /* atomic removed: atomic calls only */
#line 56
  RandomMlcgC__seed = (uint32_t )(TOS_NODE_ID + 1);

  return SUCCESS;
}

# 52 "/home/wtiberti/WSN/tinyos/tos/interfaces/Random.nc"
inline static uint16_t UniqueSendP__Random__rand16(void ){
#line 52
  unsigned short __nesc_result;
#line 52

#line 52
  __nesc_result = RandomMlcgC__Random__rand16();
#line 52

#line 52
  return __nesc_result;
#line 52
}
#line 52
# 62 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/unique/UniqueSendP.nc"
static inline error_t UniqueSendP__Init__init(void )
#line 62
{
  UniqueSendP__localSendId = UniqueSendP__Random__rand16();
  return SUCCESS;
}

# 71 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/unique/UniqueReceiveP.nc"
static inline error_t UniqueReceiveP__Init__init(void )
#line 71
{
  int i;

#line 73
  for (i = 0; i < 4; i++) {
      UniqueReceiveP__receivedMessages[i].source = (am_addr_t )0xFFFF;
      UniqueReceiveP__receivedMessages[i].dsn = 0;
    }
  return SUCCESS;
}

# 55 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
static inline error_t /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__Init__init(void )
#line 55
{
  memset(/*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__resQ, /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__NO_ENTRY, sizeof /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__resQ);
  return SUCCESS;
}

# 151 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128UartP.nc"
static inline error_t HplAtm128UartP__HplUart0__enableRxIntr(void )
#line 151
{
  * (volatile uint8_t *)(0x0A + 0x20) |= 1 << 7;
  return SUCCESS;
}

# 42 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
inline static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__enableRxIntr(void ){
#line 42
  enum __nesc_unnamed4242 __nesc_result;
#line 42

#line 42
  __nesc_result = HplAtm128UartP__HplUart0__enableRxIntr();
#line 42

#line 42
  return __nesc_result;
#line 42
}
#line 42
# 52 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerState.nc"
inline static void HplAtm128UartP__McuPowerState__update(void ){
#line 52
  McuSleepC__McuPowerState__update();
#line 52
}
#line 52
# 128 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128UartP.nc"
static inline error_t HplAtm128UartP__Uart0RxControl__start(void )
#line 128
{
  * (volatile uint8_t *)(0x0A + 0x20) |= 1 << 4;
  HplAtm128UartP__McuPowerState__update();
  return SUCCESS;
}

# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
inline static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUartRxControl__start(void ){
#line 95
  enum __nesc_unnamed4242 __nesc_result;
#line 95

#line 95
  __nesc_result = HplAtm128UartP__Uart0RxControl__start();
#line 95

#line 95
  return __nesc_result;
#line 95
}
#line 95
# 116 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128UartP.nc"
static inline error_t HplAtm128UartP__Uart0TxControl__start(void )
#line 116
{
  * (volatile uint8_t *)(0x0A + 0x20) |= 1 << 3;
  HplAtm128UartP__McuPowerState__update();
  return SUCCESS;
}

# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
inline static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUartTxControl__start(void ){
#line 95
  enum __nesc_unnamed4242 __nesc_result;
#line 95

#line 95
  __nesc_result = HplAtm128UartP__Uart0TxControl__start();
#line 95

#line 95
  return __nesc_result;
#line 95
}
#line 95
# 156 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128UartP.nc"
static inline error_t HplAtm128UartP__HplUart0__disableRxIntr(void )
#line 156
{
  * (volatile uint8_t *)(0x0A + 0x20) &= ~(1 << 7);
  return SUCCESS;
}

# 43 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
inline static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__disableRxIntr(void ){
#line 43
  enum __nesc_unnamed4242 __nesc_result;
#line 43

#line 43
  __nesc_result = HplAtm128UartP__HplUart0__disableRxIntr();
#line 43

#line 43
  return __nesc_result;
#line 43
}
#line 43
# 146 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128UartP.nc"
static inline error_t HplAtm128UartP__HplUart0__disableTxIntr(void )
#line 146
{
  * (volatile uint8_t *)(0x0A + 0x20) &= ~(1 << 6);
  return SUCCESS;
}

# 41 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
inline static error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__disableTxIntr(void ){
#line 41
  enum __nesc_unnamed4242 __nesc_result;
#line 41

#line 41
  __nesc_result = HplAtm128UartP__HplUart0__disableTxIntr();
#line 41

#line 41
  return __nesc_result;
#line 41
}
#line 41
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/Atm128UartP.nc"
static inline error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__StdControl__start(void )
#line 81
{

  /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__disableTxIntr();
  /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__disableRxIntr();
  /*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_intr = 0;
  /*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_intr = 0;


  /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUartTxControl__start();
  /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUartRxControl__start();


  /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__enableRxIntr();
  return SUCCESS;
}

# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
inline static error_t SerialPrintfP__UartControl__start(void ){
#line 95
  enum __nesc_unnamed4242 __nesc_result;
#line 95

#line 95
  __nesc_result = /*Atm128Uart0C.UartP*/Atm128UartP__0__StdControl__start();
#line 95

#line 95
  return __nesc_result;
#line 95
}
#line 95
# 54 "/home/wtiberti/WSN/tinyos/tos/lib/printf/SerialPrintfP.nc"
static inline error_t SerialPrintfP__StdControl__start(void )
{
  return SerialPrintfP__UartControl__start();
}

#line 50
static inline error_t SerialPrintfP__Init__init(void )
#line 50
{
  return SerialPrintfP__StdControl__start();
}

# 73 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/Atm128UartP.nc"
static inline error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__Init__init(void )
#line 73
{
  if (PLATFORM_BAUDRATE == 19200UL) {
    /*Atm128Uart0C.UartP*/Atm128UartP__0__m_byte_time = 200;
    }
  else {
#line 76
    if (PLATFORM_BAUDRATE == 57600UL) {
      /*Atm128Uart0C.UartP*/Atm128UartP__0__m_byte_time = 68;
      }
    }
#line 78
  return SUCCESS;
}

# 120 "/home/wtiberti/WSN/tinyos/tos/platforms/mica/MeasureClockC.nc"
static inline uint16_t MeasureClockC__Atm128Calibrate__baudrateRegister(uint32_t baudrate)
#line 120
{

  return ((uint32_t )MeasureClockC__cycles << 12) / baudrate - 1;
}

# 60 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128Calibrate.nc"
inline static uint16_t HplAtm128UartP__Atm128Calibrate__baudrateRegister(uint32_t baudrate){
#line 60
  unsigned short __nesc_result;
#line 60

#line 60
  __nesc_result = MeasureClockC__Atm128Calibrate__baudrateRegister(baudrate);
#line 60

#line 60
  return __nesc_result;
#line 60
}
#line 60
# 190 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128UartP.nc"
static inline error_t HplAtm128UartP__Uart1Init__init(void )
#line 190
{
  Atm128UartMode_t mode;
  Atm128UartStatus_t stts;
  Atm128UartControl_t ctrl;
  uint16_t ubrr1;

  ctrl.bits = (struct Atm128_UCSRB_t ){ .rxcie = 0, .txcie = 0, .rxen = 0, .txen = 0 };
  stts.bits = (struct Atm128_UCSRA_t ){ .u2x = 1 };
  mode.bits = (struct Atm128_UCSRC_t ){ .ucsz = ATM128_UART_DATA_SIZE_8_BITS };

  ubrr1 = HplAtm128UartP__Atm128Calibrate__baudrateRegister(PLATFORM_BAUDRATE);
  * (volatile uint8_t *)0x99 = ubrr1;
  * (volatile uint8_t *)0x98 = ubrr1 >> 8;
  * (volatile uint8_t *)0x9B = stts.flat;
  * (volatile uint8_t *)0x9D = mode.flat;
  * (volatile uint8_t *)0x9A = ctrl.flat;

  return SUCCESS;
}

#line 96
static inline error_t HplAtm128UartP__Uart0Init__init(void )
#line 96
{
  Atm128UartMode_t mode;
  Atm128UartStatus_t stts;
  Atm128UartControl_t ctrl;
  uint16_t ubrr0;

  ctrl.bits = (struct Atm128_UCSRB_t ){ .rxcie = 0, .txcie = 0, .rxen = 0, .txen = 0 };
  stts.bits = (struct Atm128_UCSRA_t ){ .u2x = 1 };
  mode.bits = (struct Atm128_UCSRC_t ){ .ucsz = ATM128_UART_DATA_SIZE_8_BITS };

  ubrr0 = HplAtm128UartP__Atm128Calibrate__baudrateRegister(PLATFORM_BAUDRATE);
  * (volatile uint8_t *)(0x09 + 0x20) = ubrr0;
  * (volatile uint8_t *)0x90 = ubrr0 >> 8;
  * (volatile uint8_t *)(0x0B + 0x20) = stts.flat;
  * (volatile uint8_t *)0x95 = mode.flat;
  * (volatile uint8_t *)(0x0A + 0x20) = ctrl.flat;

  return SUCCESS;
}

# 98 "/home/wtiberti/WSN/tinyos/tos/lib/printf/PutcharP.nc"
static inline error_t PutcharP__Init__init(void )
#line 98
{
  error_t rv = SUCCESS;

  __iob[1] = &atm128_stdout;

  return rv;
}

# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
inline static error_t RealMainP__SoftwareInit__init(void ){
#line 62
  enum __nesc_unnamed4242 __nesc_result;
#line 62

#line 62
  __nesc_result = PutcharP__Init__init();
#line 62
  __nesc_result = ecombine(__nesc_result, HplAtm128UartP__Uart0Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, HplAtm128UartP__Uart1Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, /*Atm128Uart0C.UartP*/Atm128UartP__0__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, SerialPrintfP__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, UniqueReceiveP__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, UniqueSendP__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, RandomMlcgC__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, CC2420ReceiveP__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, CC2420TransmitP__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, NoInitC__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, /*Atm128SpiC.Arbiter.Queue*/FcfsResourceQueueC__1__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, StateImplP__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, CC2420ControlP__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Init__init());
#line 62

#line 62
  return __nesc_result;
#line 62
}
#line 62
# 4 "../TAKS.nc"
inline static void BlinkToRadioC__TAKS__ComponentFromHexString(uint8_t *data, const char *s){
#line 4
  TAKSM__TAKS__ComponentFromHexString(data, s);
#line 4
}
#line 4
# 41 "BlinkToRadioC.nc"
static inline void BlinkToRadioC__Boot__booted(void )
#line 41
{
  char *LKCc;
#line 42
  char *dTKCc;
#line 42
  char *sTKCc;

#line 43
  if (TOS_NODE_ID == 0) {
      LKCc = "1F598C9C83D8213F61975A621E10320CE4C182FDC07A92C55009A48209E63308";
      dTKCc = "5C16A98C1889BCA4BF9AA9C8042CD83A729FA9B4F71384668C793C7B2070C36D";
      sTKCc = "6034A63B434633E0F2AC5557917796405463B5410F273D82786DC845D7D15780";
    }
  else 
#line 47
    {
      LKCc = "9BC71C4CBD4B26CE9E5EBC3DD4C777FD42A81703C8DE3E717BF5200E622EA292";
      dTKCc = "6034A63B434633E0F2AC5557917796405463B5410F273D82786DC845D7D15780";
      sTKCc = "5C16A98C1889BCA4BF9AA9C8042CD83A729FA9B4F71384668C793C7B2070C36D";
    }
  BlinkToRadioC__TAKS__ComponentFromHexString(BlinkToRadioC__LKC, LKCc);
  BlinkToRadioC__TAKS__ComponentFromHexString(BlinkToRadioC__dTKC, dTKCc);
  BlinkToRadioC__TAKS__ComponentFromHexString(BlinkToRadioC__sTKC, sTKCc);
  BlinkToRadioC__AMControl__start();
}

# 60 "/home/wtiberti/WSN/tinyos/tos/interfaces/Boot.nc"
inline static void RealMainP__Boot__booted(void ){
#line 60
  BlinkToRadioC__Boot__booted();
#line 60
}
#line 60
# 150 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
static inline void SchedulerBasicP__trace_task_end(uint16_t num, uint32_t delta)
#line 150
{
}

#line 147
static inline uint32_t SchedulerBasicP__trace_usecsRaw(void )
#line 147
{
#line 147
  return 0;
}

#line 149
static inline void SchedulerBasicP__trace_task_start(uint16_t num)
#line 149
{
}

# 164 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer0AsyncP.nc"
static inline mcu_power_t HplAtm128Timer0AsyncP__McuPowerOverride__lowestState(void )
#line 164
{
  uint8_t diff;


  if (* (volatile uint8_t *)(0x37 + 0x20) & ((1 << 1) | (1 << 0))) {




      while (* (volatile uint8_t *)(0x30 + 0x20) & (((1 << 2) | (1 << 1)) | (1 << 0))) 
        ;
      diff = * (volatile uint8_t *)(0x31 + 0x20) - * (volatile uint8_t *)(0x32 + 0x20);
      if (diff < EXT_STANDBY_T0_THRESHOLD || 
      * (volatile uint8_t *)(0x32 + 0x20) > 256 - EXT_STANDBY_T0_THRESHOLD) {
        return ATM128_POWER_EXT_STANDBY;
        }
#line 179
      return ATM128_POWER_SAVE;
    }
  else {
      return ATM128_POWER_DOWN;
    }
}

# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerOverride.nc"
inline static mcu_power_t McuSleepC__McuPowerOverride__lowestState(void ){
#line 62
  unsigned char __nesc_result;
#line 62

#line 62
  __nesc_result = HplAtm128Timer0AsyncP__McuPowerOverride__lowestState();
#line 62

#line 62
  return __nesc_result;
#line 62
}
#line 62
# 72 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/McuSleepC.nc"
static inline mcu_power_t McuSleepC__getPowerState(void )
#line 72
{





  if (* (volatile uint8_t *)(0x37 + 0x20) & ~((((1 << 1) | (1 << 0)) | (1 << 2)) | (1 << 6)) || 
  * (volatile uint8_t *)0x7D & ~(1 << 2)) {
      return ATM128_POWER_IDLE;
    }
  else {
    if (* (volatile uint8_t *)(uint16_t )& * (volatile uint8_t *)(0x0D + 0x20) & (1 << 6)) {
        return ATM128_POWER_IDLE;
      }
    else {
      if ((* (volatile uint8_t *)(0x0A + 0x20) | * (volatile uint8_t *)0x9A) & ((1 << 3) | (1 << 4))) {
          return ATM128_POWER_IDLE;
        }
      else {
        if (* (volatile uint8_t *)(uint16_t )& * (volatile uint8_t *)0x74 & (1 << 2)) {
            return ATM128_POWER_IDLE;
          }
        else {
          if (* (volatile uint8_t *)(uint16_t )& * (volatile uint8_t *)(0x06 + 0x20) & (1 << 7)) {
              return ATM128_POWER_ADC_NR;
            }
          else {
              return ATM128_POWER_DOWN;
            }
          }
        }
      }
    }
}

# 140 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/atm128hardware.h"
static inline  mcu_power_t mcombine(mcu_power_t m1, mcu_power_t m2)
#line 140
{
  return m1 < m2 ? m1 : m2;
}

# 103 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/McuSleepC.nc"
static inline void McuSleepC__McuSleep__sleep(void )
#line 103
{
  uint8_t powerState;

  powerState = mcombine(McuSleepC__getPowerState(), McuSleepC__McuPowerOverride__lowestState());
  * (volatile uint8_t *)(0x35 + 0x20) = ((
  * (volatile uint8_t *)(0x35 + 0x20) & 0xe3) | (1 << 5)) | __extension__ ({
#line 108
    uint16_t __addr16 = (uint16_t )(uint16_t )&McuSleepC__atm128PowerBits[powerState];
#line 108
    uint8_t __result;

#line 108
     __asm volatile ("lpm %0, Z""\n\t" : "=r"(__result) : "z"(__addr16));__result;
  }
  );
#line 110
   __asm volatile ("sei" :  :  : "memory");

   __asm volatile ("sleep" :  :  : "memory");
   __asm volatile ("cli" :  :  : "memory");

  * (volatile uint8_t *)(0x35 + 0x20) &= ~(1 << 5);
}

# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuSleep.nc"
inline static void SchedulerBasicP__McuSleep__sleep(void ){
#line 79
  McuSleepC__McuSleep__sleep();
#line 79
}
#line 79
# 161 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
static __inline uint8_t SchedulerBasicP__popTask(void )
#line 161
{
  if (SchedulerBasicP__m_head != SchedulerBasicP__NO_TASK) {
      uint8_t id = SchedulerBasicP__m_head;

      SchedulerBasicP__m_head = SchedulerBasicP__m_next[SchedulerBasicP__m_head];
      if (SchedulerBasicP__m_head == SchedulerBasicP__NO_TASK) {
          SchedulerBasicP__m_tail = SchedulerBasicP__NO_TASK;
        }
      SchedulerBasicP__m_next[id] = SchedulerBasicP__NO_TASK;
      return id;
    }
  else {
#line 172
    return SchedulerBasicP__NO_TASK;
    }
}

#line 213
static inline void SchedulerBasicP__Scheduler__taskLoop(void )
#line 213
{
  uint32_t delta;

  for (; ; ) {
      { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 217
        {
          while ((SchedulerBasicP__lastTask = SchedulerBasicP__popTask()) == SchedulerBasicP__NO_TASK) {

              SchedulerBasicP__McuSleep__sleep();
            }
        }
#line 222
        __nesc_atomic_end(__nesc_atomic); }
      SchedulerBasicP__trace_task_start(SchedulerBasicP__lastTask);
      delta = SchedulerBasicP__trace_usecsRaw();

      SchedulerBasicP__TaskBasic__runTask(SchedulerBasicP__lastTask);
      delta = SchedulerBasicP__trace_usecsRaw() - delta;
      SchedulerBasicP__trace_task_end(SchedulerBasicP__lastTask, delta);
    }
}

# 72 "/home/wtiberti/WSN/tinyos/tos/interfaces/Scheduler.nc"
inline static void RealMainP__Scheduler__taskLoop(void ){
#line 72
  SchedulerBasicP__Scheduler__taskLoop();
#line 72
}
#line 72
# 149 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer0AsyncP.nc"
static __inline void HplAtm128Timer0AsyncP__stabiliseTimer0(void )
#line 149
{
  * (volatile uint8_t *)(0x33 + 0x20) = * (volatile uint8_t *)(0x33 + 0x20);
  while (* (volatile uint8_t *)(0x30 + 0x20) & (1 << 0)) 
    ;
}

# 58 "/home/wtiberti/WSN/tinyos/tos/lib/timer/CounterToLocalTimeC.nc"
static inline void /*HilTimerMilliC.CounterToLocalTimeC*/CounterToLocalTimeC__0__Counter__overflow(void )
{
}

# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Counter__overflow(void ){
#line 82
  /*HilTimerMilliC.CounterToLocalTimeC*/CounterToLocalTimeC__0__Counter__overflow();
#line 82
}
#line 82
# 88 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/atm128hardware.h"
static __inline  void __nesc_enable_interrupt()
#line 88
{
   __asm volatile ("sei" :  :  : "memory");}

# 141 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer0AsyncP.nc"
static inline uint8_t HplAtm128Timer0AsyncP__Compare__get(void )
#line 141
{
#line 141
  return * (volatile uint8_t *)(0x31 + 0x20);
}

# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__size_type /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__get(void ){
#line 48
  unsigned char __nesc_result;
#line 48

#line 48
  __nesc_result = HplAtm128Timer0AsyncP__Compare__get();
#line 48

#line 48
  return __nesc_result;
#line 48
}
#line 48
# 149 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmAsyncP.nc"
static inline void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__fired(void )
#line 149
{
  int overflowed;


  /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__base += /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__get() + 1U;
  overflowed = !/*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__base;
  __nesc_enable_interrupt();
  /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__setInterrupt();
  if (overflowed) {
    /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Counter__overflow();
    }
}

# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void HplAtm128Timer0AsyncP__Compare__fired(void ){
#line 58
  /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__fired();
#line 58
}
#line 58
# 230 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmAsyncP.nc"
static inline void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__overflow(void )
#line 230
{
}

# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static void HplAtm128Timer0AsyncP__Timer__overflow(void ){
#line 70
  /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__overflow();
#line 70
}
#line 70
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420ControlP__SpiResource__request(void ){
#line 88
  enum __nesc_unnamed4242 __nesc_result;
#line 88

#line 88
  __nesc_result = CC2420SpiP__Resource__request(/*CC2420ControlC.Spi*/CC2420SpiC__0__CLIENT_ID);
#line 88

#line 88
  return __nesc_result;
#line 88
}
#line 88
# 188 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline error_t CC2420ControlP__Resource__request(void )
#line 188
{
  return CC2420ControlP__SpiResource__request();
}

# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420CsmaP__Resource__request(void ){
#line 88
  enum __nesc_unnamed4242 __nesc_result;
#line 88

#line 88
  __nesc_result = CC2420ControlP__Resource__request();
#line 88

#line 88
  return __nesc_result;
#line 88
}
#line 88
# 210 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
static inline void CC2420CsmaP__CC2420Power__startVRegDone(void )
#line 210
{
  CC2420CsmaP__Resource__request();
}

# 56 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Power.nc"
inline static void CC2420ControlP__CC2420Power__startVRegDone(void ){
#line 56
  CC2420CsmaP__CC2420Power__startVRegDone();
#line 56
}
#line 56
# 431 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static inline void CC2420ControlP__StartupTimer__fired(void )
#line 431
{
  if (CC2420ControlP__m_state == CC2420ControlP__S_VREG_STARTING) {
      CC2420ControlP__m_state = CC2420ControlP__S_VREG_STARTED;
      CC2420ControlP__RSTN__clr();
      CC2420ControlP__RSTN__set();
      CC2420ControlP__CC2420Power__startVRegDone();
    }
}

# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static bool CC2420TransmitP__CCA__get(void ){
#line 43
  unsigned char __nesc_result;
#line 43

#line 43
  __nesc_result = /*HplAtm128GeneralIOC.PortD.Bit6*/HplAtm128GeneralIOPinP__30__IO__get();
#line 43

#line 43
  return __nesc_result;
#line 43
}
#line 43
# 498 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static inline void CC2420TransmitP__BackoffTimer__fired(void )
#line 498
{
  /* atomic removed: atomic calls only */
#line 499
  {
    switch (CC2420TransmitP__m_state) {

        case CC2420TransmitP__S_SAMPLE_CCA: 


          if (CC2420TransmitP__CCA__get()) {
              CC2420TransmitP__m_state = CC2420TransmitP__S_BEGIN_TRANSMIT;
              CC2420TransmitP__BackoffTimer__start(CC2420_TIME_ACK_TURNAROUND);
            }
          else {
              CC2420TransmitP__congestionBackoff();
            }
        break;

        case CC2420TransmitP__S_BEGIN_TRANSMIT: 
          case CC2420TransmitP__S_CANCEL: 
            if (CC2420TransmitP__acquireSpiResource() == SUCCESS) {
                CC2420TransmitP__attemptSend();
              }
        break;

        case CC2420TransmitP__S_ACK_WAIT: 
          CC2420TransmitP__signalDone(SUCCESS);
        break;

        case CC2420TransmitP__S_SFD: 


          CC2420TransmitP__SFLUSHTX__strobe();
        CC2420TransmitP__CaptureSFD__captureRisingEdge();
        CC2420TransmitP__releaseSpiResource();
        CC2420TransmitP__signalDone(ERETRY);
        break;

        default: 
          break;
      }
  }
}

# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__fired(void ){
#line 78
  CC2420TransmitP__BackoffTimer__fired();
#line 78
  CC2420ControlP__StartupTimer__fired();
#line 78
}
#line 78
# 162 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__fired(void )
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      if (/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_dt == 0) 
        {
          /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__fired();
        }
      else 
        {
          /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__set_alarm();
        }
    }
#line 174
    __nesc_atomic_end(__nesc_atomic); }
}

# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__fired(void ){
#line 78
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__fired();
#line 78
}
#line 78
# 119 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__fired(void )
#line 119
{
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__stop();
  ;
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__Alarm__fired();
}

# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void HplAtm128Timer1P__CompareA__fired(void ){
#line 58
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Compare__fired();
#line 58
}
#line 58
# 207 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline void HplAtm128Timer1P__CompareB__default__fired(void )
#line 207
{
}

# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void HplAtm128Timer1P__CompareB__fired(void ){
#line 58
  HplAtm128Timer1P__CompareB__default__fired();
#line 58
}
#line 58
# 211 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline void HplAtm128Timer1P__CompareC__default__fired(void )
#line 211
{
}

# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void HplAtm128Timer1P__CompareC__fired(void ){
#line 58
  HplAtm128Timer1P__CompareC__default__fired();
#line 58
}
#line 58
# 340 "/usr/local/lib/ncc/nesc_nx.h"
static __inline  uint32_t __nesc_ntoh_uint32(const void * source)
#line 340
{
  const uint8_t *base = source;

#line 342
  return ((((uint32_t )base[0] << 24) | (
  (uint32_t )base[1] << 16)) | (
  (uint32_t )base[2] << 8)) | base[3];
}

# 70 "/home/wtiberti/WSN/tinyos/tos/interfaces/PacketTimeStamp.nc"
inline static void CC2420TransmitP__PacketTimeStamp__clear(message_t * msg){
#line 70
  CC2420PacketP__PacketTimeStamp32khz__clear(msg);
#line 70
}
#line 70
# 195 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static inline void CC2420ReceiveP__CC2420Receive__sfd_dropped(void )
#line 195
{
  if (CC2420ReceiveP__m_timestamp_size) {
      CC2420ReceiveP__m_timestamp_size--;
    }
}

# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Receive.nc"
inline static void CC2420TransmitP__CC2420Receive__sfd_dropped(void ){
#line 55
  CC2420ReceiveP__CC2420Receive__sfd_dropped();
#line 55
}
#line 55
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128GeneralIOPinP.nc"
static __inline bool /*HplAtm128GeneralIOC.PortD.Bit4*/HplAtm128GeneralIOPinP__28__IO__get(void )
#line 54
{
#line 54
  return (* (volatile uint8_t * )48U & (1 << 4)) != 0;
}

# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static bool CC2420TransmitP__SFD__get(void ){
#line 43
  unsigned char __nesc_result;
#line 43

#line 43
  __nesc_result = /*HplAtm128GeneralIOC.PortD.Bit4*/HplAtm128GeneralIOPinP__28__IO__get();
#line 43

#line 43
  return __nesc_result;
#line 43
}
#line 43
# 186 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static inline void CC2420ReceiveP__CC2420Receive__sfd(uint32_t time)
#line 186
{
  if (CC2420ReceiveP__m_timestamp_size < CC2420ReceiveP__TIMESTAMP_QUEUE_SIZE) {
      uint8_t tail = (CC2420ReceiveP__m_timestamp_head + CC2420ReceiveP__m_timestamp_size) % 
      CC2420ReceiveP__TIMESTAMP_QUEUE_SIZE;

#line 190
      CC2420ReceiveP__m_timestamp_queue[tail] = time;
      CC2420ReceiveP__m_timestamp_size++;
    }
}

# 49 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Receive.nc"
inline static void CC2420TransmitP__CC2420Receive__sfd(uint32_t time){
#line 49
  CC2420ReceiveP__CC2420Receive__sfd(time);
#line 49
}
#line 49
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128GpioCaptureC.nc"
static inline error_t /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__captureFallingEdge(void )
#line 63
{
  return /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__enableCapture(FALSE);
}

# 54 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
inline static error_t CC2420TransmitP__CaptureSFD__captureFallingEdge(void ){
#line 54
  enum __nesc_unnamed4242 __nesc_result;
#line 54

#line 54
  __nesc_result = /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__captureFallingEdge();
#line 54

#line 54
  return __nesc_result;
#line 54
}
#line 54
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Ram.nc"
inline static cc2420_status_t CC2420TransmitP__TXFIFO_RAM__write(uint8_t offset, uint8_t * data, uint8_t length){
#line 63
  unsigned char __nesc_result;
#line 63

#line 63
  __nesc_result = CC2420SpiP__Ram__write(CC2420_RAM_TXFIFO, offset, data, length);
#line 63

#line 63
  return __nesc_result;
#line 63
}
#line 63
# 219 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/packet/CC2420PacketP.nc"
static inline uint8_t CC2420PacketP__PacketTimeSyncOffset__get(message_t *msg)
{
  return __nesc_ntoh_leuint8(CC2420PacketP__CC2420PacketBody__getHeader(msg)->length.nxdata)
   + (sizeof(cc2420_header_t ) - MAC_HEADER_SIZE)
   - MAC_FOOTER_SIZE
   - sizeof(timesync_radio_t );
}

# 58 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/PacketTimeSyncOffset.nc"
inline static uint8_t CC2420TransmitP__PacketTimeSyncOffset__get(message_t * msg){
#line 58
  unsigned char __nesc_result;
#line 58

#line 58
  __nesc_result = CC2420PacketP__PacketTimeSyncOffset__get(msg);
#line 58

#line 58
  return __nesc_result;
#line 58
}
#line 58
# 210 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/packet/CC2420PacketP.nc"
static inline bool CC2420PacketP__PacketTimeSyncOffset__isSet(message_t *msg)
{
  return __nesc_ntoh_int8(CC2420PacketP__CC2420PacketBody__getMetadata(msg)->timesync.nxdata);
}

# 50 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/PacketTimeSyncOffset.nc"
inline static bool CC2420TransmitP__PacketTimeSyncOffset__isSet(message_t * msg){
#line 50
  unsigned char __nesc_result;
#line 50

#line 50
  __nesc_result = CC2420PacketP__PacketTimeSyncOffset__isSet(msg);
#line 50

#line 50
  return __nesc_result;
#line 50
}
#line 50
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/PacketTimeStamp.nc"
inline static void CC2420TransmitP__PacketTimeStamp__set(message_t * msg, CC2420TransmitP__PacketTimeStamp__size_type value){
#line 78
  CC2420PacketP__PacketTimeStamp32khz__set(msg, value);
#line 78
}
#line 78
# 109 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static CC2420TransmitP__BackoffTimer__size_type CC2420TransmitP__BackoffTimer__getNow(void ){
#line 109
  unsigned long __nesc_result;
#line 109

#line 109
  __nesc_result = /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__getNow();
#line 109

#line 109
  return __nesc_result;
#line 109
}
#line 109
# 259 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static __inline uint32_t CC2420TransmitP__getTime32(uint16_t captured_time)
{
  uint32_t now = CC2420TransmitP__BackoffTimer__getNow();


  return now - (uint16_t )(now - captured_time);
}

#line 280
static inline void CC2420TransmitP__CaptureSFD__captured(uint16_t time)
#line 280
{
  unsigned char *__nesc_temp45;
  unsigned char *__nesc_temp44;
#line 281
  uint32_t time32;
  uint8_t sfd_state = 0;

#line 283
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 283
    {
      time32 = CC2420TransmitP__getTime32(time);
      switch (CC2420TransmitP__m_state) {

          case CC2420TransmitP__S_SFD: 
            CC2420TransmitP__m_state = CC2420TransmitP__S_EFD;
          CC2420TransmitP__sfdHigh = TRUE;


          CC2420TransmitP__m_receiving = FALSE;
          CC2420TransmitP__CaptureSFD__captureFallingEdge();
          CC2420TransmitP__PacketTimeStamp__set(CC2420TransmitP__m_msg, time32);
          if (CC2420TransmitP__PacketTimeSyncOffset__isSet(CC2420TransmitP__m_msg)) {
              uint8_t absOffset = sizeof(message_header_t ) - sizeof(cc2420_header_t ) + CC2420TransmitP__PacketTimeSyncOffset__get(CC2420TransmitP__m_msg);
              timesync_radio_t *timesync = (timesync_radio_t *)((nx_uint8_t *)CC2420TransmitP__m_msg + absOffset);

              (__nesc_temp44 = (*timesync).nxdata, __nesc_hton_uint32(__nesc_temp44, __nesc_ntoh_uint32(__nesc_temp44) - time32));
              CC2420TransmitP__CSN__clr();
              CC2420TransmitP__TXFIFO_RAM__write(absOffset, (uint8_t *)timesync, sizeof(timesync_radio_t ));
              CC2420TransmitP__CSN__set();

              (__nesc_temp45 = (*timesync).nxdata, __nesc_hton_uint32(__nesc_temp45, __nesc_ntoh_uint32(__nesc_temp45) + time32));
            }

          if (__nesc_ntoh_leuint16(CC2420TransmitP__CC2420PacketBody__getHeader(CC2420TransmitP__m_msg)->fcf.nxdata) & (1 << IEEE154_FCF_ACK_REQ)) {

              CC2420TransmitP__abortSpiRelease = TRUE;
            }
          CC2420TransmitP__releaseSpiResource();
          CC2420TransmitP__BackoffTimer__stop();

          if (CC2420TransmitP__SFD__get()) {
              break;
            }


          case CC2420TransmitP__S_EFD: 
            CC2420TransmitP__sfdHigh = FALSE;
          CC2420TransmitP__CaptureSFD__captureRisingEdge();

          if (__nesc_ntoh_leuint16(CC2420TransmitP__CC2420PacketBody__getHeader(CC2420TransmitP__m_msg)->fcf.nxdata) & (1 << IEEE154_FCF_ACK_REQ)) {
              CC2420TransmitP__m_state = CC2420TransmitP__S_ACK_WAIT;
              CC2420TransmitP__BackoffTimer__start(CC2420_ACK_WAIT_DELAY);
            }
          else 
#line 326
            {
              CC2420TransmitP__signalDone(SUCCESS);
            }

          if (!CC2420TransmitP__SFD__get()) {
              break;
            }


          default: 

            if (!CC2420TransmitP__m_receiving && CC2420TransmitP__sfdHigh == FALSE) {
                CC2420TransmitP__sfdHigh = TRUE;
                CC2420TransmitP__CaptureSFD__captureFallingEdge();

                sfd_state = CC2420TransmitP__SFD__get();
                CC2420TransmitP__CC2420Receive__sfd(time32);
                CC2420TransmitP__m_receiving = TRUE;
                CC2420TransmitP__m_prev_time = time;
                if (CC2420TransmitP__SFD__get()) {
                    {
                      __nesc_atomic_end(__nesc_atomic); 
#line 347
                      return;
                    }
                  }
              }


          if (CC2420TransmitP__sfdHigh == TRUE) {
              CC2420TransmitP__sfdHigh = FALSE;
              CC2420TransmitP__CaptureSFD__captureRisingEdge();
              CC2420TransmitP__m_receiving = FALSE;








              if (sfd_state == 0 && time - CC2420TransmitP__m_prev_time < 10) {
                  CC2420TransmitP__CC2420Receive__sfd_dropped();
                  if (CC2420TransmitP__m_msg) {
                    CC2420TransmitP__PacketTimeStamp__clear(CC2420TransmitP__m_msg);
                    }
                }
#line 370
              break;
            }
        }
    }
#line 373
    __nesc_atomic_end(__nesc_atomic); }
}

# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__captured(uint16_t time){
#line 61
  CC2420TransmitP__CaptureSFD__captured(time);
#line 61
}
#line 61
# 71 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128GpioCaptureC.nc"
static inline void /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__captured(uint16_t time)
#line 71
{


  /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Capture__captured(time);
}

# 60 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Capture.nc"
inline static void HplAtm128Timer1P__Capture__captured(HplAtm128Timer1P__Capture__size_type t){
#line 60
  /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__captured(t);
#line 60
}
#line 60
# 197 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
static inline uint16_t HplAtm128Timer1P__Capture__get(void )
#line 197
{
#line 197
  return * (volatile uint16_t *)(0x26 + 0x20);
}

# 125 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Timer__overflow(void )
#line 125
{
}

# 60 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128TimerInitC.nc"
static inline void /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__overflow(void )
#line 60
{
}

# 177 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Counter__overflow(void )
{
}

# 58 "/home/wtiberti/WSN/tinyos/tos/lib/timer/CounterToLocalTimeC.nc"
static inline void /*CC2420PacketC.CounterToLocalTimeC*/CounterToLocalTimeC__1__Counter__overflow(void )
{
}

# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static void /*Counter32khz32C.Transform32*/TransformCounterC__0__Counter__overflow(void ){
#line 82
  /*CC2420PacketC.CounterToLocalTimeC*/CounterToLocalTimeC__1__Counter__overflow();
#line 82
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Counter__overflow();
#line 82
}
#line 82
# 133 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
static inline void /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__overflow(void )
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      /*Counter32khz32C.Transform32*/TransformCounterC__0__m_upper++;
      if ((/*Counter32khz32C.Transform32*/TransformCounterC__0__m_upper & /*Counter32khz32C.Transform32*/TransformCounterC__0__OVERFLOW_MASK) == 0) {
        /*Counter32khz32C.Transform32*/TransformCounterC__0__Counter__overflow();
        }
    }
#line 141
    __nesc_atomic_end(__nesc_atomic); }
}

# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static void /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__overflow(void ){
#line 82
  /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__overflow();
#line 82
}
#line 82
# 65 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128CounterC.nc"
static inline void /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__overflow(void )
{
  /*CounterOne16C.NCounter*/Atm128CounterC__0__Counter__overflow();
}

# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static void HplAtm128Timer1P__Timer__overflow(void ){
#line 70
  /*CounterOne16C.NCounter*/Atm128CounterC__0__Timer__overflow();
#line 70
  /*InitOneP.InitOne*/Atm128TimerInitC__0__Timer__overflow();
#line 70
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Alarm16.NAlarm*/Atm128AlarmC__0__HplAtm128Timer__overflow();
#line 70
}
#line 70
# 72 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin0*/HplAtm128InterruptPinP__0__Irq__default__fired(void )
#line 72
{
}

# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
inline static void /*HplAtm128InterruptC.IntPin0*/HplAtm128InterruptPinP__0__Irq__fired(void ){
#line 75
  /*HplAtm128InterruptC.IntPin0*/HplAtm128InterruptPinP__0__Irq__default__fired();
#line 75
}
#line 75
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin0*/HplAtm128InterruptPinP__0__IrqSignal__fired(void )
#line 70
{
#line 70
  /*HplAtm128InterruptC.IntPin0*/HplAtm128InterruptPinP__0__Irq__fired();
}

# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
inline static void HplAtm128InterruptSigP__IntSig0__fired(void ){
#line 48
  /*HplAtm128InterruptC.IntPin0*/HplAtm128InterruptPinP__0__IrqSignal__fired();
#line 48
}
#line 48
# 72 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin1*/HplAtm128InterruptPinP__1__Irq__default__fired(void )
#line 72
{
}

# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
inline static void /*HplAtm128InterruptC.IntPin1*/HplAtm128InterruptPinP__1__Irq__fired(void ){
#line 75
  /*HplAtm128InterruptC.IntPin1*/HplAtm128InterruptPinP__1__Irq__default__fired();
#line 75
}
#line 75
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin1*/HplAtm128InterruptPinP__1__IrqSignal__fired(void )
#line 70
{
#line 70
  /*HplAtm128InterruptC.IntPin1*/HplAtm128InterruptPinP__1__Irq__fired();
}

# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
inline static void HplAtm128InterruptSigP__IntSig1__fired(void ){
#line 48
  /*HplAtm128InterruptC.IntPin1*/HplAtm128InterruptPinP__1__IrqSignal__fired();
#line 48
}
#line 48
# 72 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin2*/HplAtm128InterruptPinP__2__Irq__default__fired(void )
#line 72
{
}

# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
inline static void /*HplAtm128InterruptC.IntPin2*/HplAtm128InterruptPinP__2__Irq__fired(void ){
#line 75
  /*HplAtm128InterruptC.IntPin2*/HplAtm128InterruptPinP__2__Irq__default__fired();
#line 75
}
#line 75
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin2*/HplAtm128InterruptPinP__2__IrqSignal__fired(void )
#line 70
{
#line 70
  /*HplAtm128InterruptC.IntPin2*/HplAtm128InterruptPinP__2__Irq__fired();
}

# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
inline static void HplAtm128InterruptSigP__IntSig2__fired(void ){
#line 48
  /*HplAtm128InterruptC.IntPin2*/HplAtm128InterruptPinP__2__IrqSignal__fired();
#line 48
}
#line 48
# 72 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin3*/HplAtm128InterruptPinP__3__Irq__default__fired(void )
#line 72
{
}

# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
inline static void /*HplAtm128InterruptC.IntPin3*/HplAtm128InterruptPinP__3__Irq__fired(void ){
#line 75
  /*HplAtm128InterruptC.IntPin3*/HplAtm128InterruptPinP__3__Irq__default__fired();
#line 75
}
#line 75
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin3*/HplAtm128InterruptPinP__3__IrqSignal__fired(void )
#line 70
{
#line 70
  /*HplAtm128InterruptC.IntPin3*/HplAtm128InterruptPinP__3__Irq__fired();
}

# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
inline static void HplAtm128InterruptSigP__IntSig3__fired(void ){
#line 48
  /*HplAtm128InterruptC.IntPin3*/HplAtm128InterruptPinP__3__IrqSignal__fired();
#line 48
}
#line 48
# 72 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin4*/HplAtm128InterruptPinP__4__Irq__default__fired(void )
#line 72
{
}

# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
inline static void /*HplAtm128InterruptC.IntPin4*/HplAtm128InterruptPinP__4__Irq__fired(void ){
#line 75
  /*HplAtm128InterruptC.IntPin4*/HplAtm128InterruptPinP__4__Irq__default__fired();
#line 75
}
#line 75
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin4*/HplAtm128InterruptPinP__4__IrqSignal__fired(void )
#line 70
{
#line 70
  /*HplAtm128InterruptC.IntPin4*/HplAtm128InterruptPinP__4__Irq__fired();
}

# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
inline static void HplAtm128InterruptSigP__IntSig4__fired(void ){
#line 48
  /*HplAtm128InterruptC.IntPin4*/HplAtm128InterruptPinP__4__IrqSignal__fired();
#line 48
}
#line 48
# 72 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin5*/HplAtm128InterruptPinP__5__Irq__default__fired(void )
#line 72
{
}

# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
inline static void /*HplAtm128InterruptC.IntPin5*/HplAtm128InterruptPinP__5__Irq__fired(void ){
#line 75
  /*HplAtm128InterruptC.IntPin5*/HplAtm128InterruptPinP__5__Irq__default__fired();
#line 75
}
#line 75
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin5*/HplAtm128InterruptPinP__5__IrqSignal__fired(void )
#line 70
{
#line 70
  /*HplAtm128InterruptC.IntPin5*/HplAtm128InterruptPinP__5__Irq__fired();
}

# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
inline static void HplAtm128InterruptSigP__IntSig5__fired(void ){
#line 48
  /*HplAtm128InterruptC.IntPin5*/HplAtm128InterruptPinP__5__IrqSignal__fired();
#line 48
}
#line 48
# 212 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static inline void CC2420ReceiveP__InterruptFIFOP__fired(void )
#line 212
{
  if (CC2420ReceiveP__m_state == CC2420ReceiveP__S_STARTED) {

      CC2420ReceiveP__m_state = CC2420ReceiveP__S_RX_LENGTH;
      CC2420ReceiveP__beginReceive();
    }
  else 



    {
      CC2420ReceiveP__m_missed_packets++;
    }
}

# 68 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Interrupt__fired(void ){
#line 68
  CC2420ReceiveP__InterruptFIFOP__fired();
#line 68
}
#line 68
# 38 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/Atm128GpioInterruptC.nc"
static inline void /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__fired(void )
#line 38
{
  /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Interrupt__fired();
}

# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
inline static void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__fired(void ){
#line 75
  /*HplCC2420InterruptsC.InterruptFIFOPC*/Atm128GpioInterruptC__0__Atm128Interrupt__fired();
#line 75
}
#line 75
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__IrqSignal__fired(void )
#line 70
{
#line 70
  /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__Irq__fired();
}

# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
inline static void HplAtm128InterruptSigP__IntSig6__fired(void ){
#line 48
  /*HplAtm128InterruptC.IntPin6*/HplAtm128InterruptPinP__6__IrqSignal__fired();
#line 48
}
#line 48
# 72 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin7*/HplAtm128InterruptPinP__7__Irq__default__fired(void )
#line 72
{
}

# 75 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128Interrupt.nc"
inline static void /*HplAtm128InterruptC.IntPin7*/HplAtm128InterruptPinP__7__Irq__fired(void ){
#line 75
  /*HplAtm128InterruptC.IntPin7*/HplAtm128InterruptPinP__7__Irq__default__fired();
#line 75
}
#line 75
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptPinP.nc"
static inline void /*HplAtm128InterruptC.IntPin7*/HplAtm128InterruptPinP__7__IrqSignal__fired(void )
#line 70
{
#line 70
  /*HplAtm128InterruptC.IntPin7*/HplAtm128InterruptPinP__7__Irq__fired();
}

# 48 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSig.nc"
inline static void HplAtm128InterruptSigP__IntSig7__fired(void ){
#line 48
  /*HplAtm128InterruptC.IntPin7*/HplAtm128InterruptPinP__7__IrqSignal__fired();
#line 48
}
#line 48
# 115 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
static inline uint8_t HplAtm128SpiP__SPI__read(void )
#line 115
{
#line 115
  return * (volatile uint8_t *)(0x0F + 0x20);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
inline static uint8_t Atm128SpiP__Spi__read(void ){
#line 97
  unsigned char __nesc_result;
#line 97

#line 97
  __nesc_result = HplAtm128SpiP__SPI__read();
#line 97

#line 97
  return __nesc_result;
#line 97
}
#line 97
#line 113
inline static void Atm128SpiP__Spi__enableInterrupt(bool enabled){
#line 113
  HplAtm128SpiP__SPI__enableInterrupt(enabled);
#line 113
}
#line 113
# 352 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128SpiP.nc"
static inline void Atm128SpiP__Spi__dataReady(uint8_t data)
#line 352
{
  bool again;

  /* atomic removed: atomic calls only */
#line 355
  {
    if (Atm128SpiP__rxBuffer != (void *)0) {
        Atm128SpiP__rxBuffer[Atm128SpiP__pos] = data;
      }

    Atm128SpiP__pos++;
  }
  Atm128SpiP__Spi__enableInterrupt(FALSE);
  /* atomic removed: atomic calls only */
  {
    again = Atm128SpiP__pos < Atm128SpiP__len;
  }

  if (again) {
      Atm128SpiP__sendNextPart();
    }
  else {
      uint8_t discard;
      uint16_t myLen;
      uint8_t * rx;
      uint8_t * tx;

      /* atomic removed: atomic calls only */
#line 377
      {
        myLen = Atm128SpiP__len;
        rx = Atm128SpiP__rxBuffer;
        tx = Atm128SpiP__txBuffer;
        Atm128SpiP__rxBuffer = (void *)0;
        Atm128SpiP__txBuffer = (void *)0;
        Atm128SpiP__len = 0;
        Atm128SpiP__pos = 0;
      }
      discard = Atm128SpiP__Spi__read();

      Atm128SpiP__SpiPacket__sendDone(tx, rx, myLen, SUCCESS);
    }
}

# 109 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128Spi.nc"
inline static void HplAtm128SpiP__SPI__dataReady(uint8_t data){
#line 109
  Atm128SpiP__Spi__dataReady(data);
#line 109
}
#line 109
# 197 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer3P.nc"
static inline void HplAtm128Timer3P__CompareA__default__fired(void )
#line 197
{
}

# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void HplAtm128Timer3P__CompareA__fired(void ){
#line 58
  HplAtm128Timer3P__CompareA__default__fired();
#line 58
}
#line 58
# 201 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer3P.nc"
static inline void HplAtm128Timer3P__CompareB__default__fired(void )
#line 201
{
}

# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void HplAtm128Timer3P__CompareB__fired(void ){
#line 58
  HplAtm128Timer3P__CompareB__default__fired();
#line 58
}
#line 58
# 205 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer3P.nc"
static inline void HplAtm128Timer3P__CompareC__default__fired(void )
#line 205
{
}

# 58 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Compare.nc"
inline static void HplAtm128Timer3P__CompareC__fired(void ){
#line 58
  HplAtm128Timer3P__CompareC__default__fired();
#line 58
}
#line 58
# 209 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer3P.nc"
static inline void HplAtm128Timer3P__Capture__default__captured(uint16_t time)
#line 209
{
}

# 60 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Capture.nc"
inline static void HplAtm128Timer3P__Capture__captured(HplAtm128Timer3P__Capture__size_type t){
#line 60
  HplAtm128Timer3P__Capture__default__captured(t);
#line 60
}
#line 60
# 191 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer3P.nc"
static inline uint16_t HplAtm128Timer3P__Capture__get(void )
#line 191
{
#line 191
  return * (volatile uint16_t *)0x80;
}

# 58 "/home/wtiberti/WSN/tinyos/tos/lib/timer/CounterToLocalTimeC.nc"
static inline void /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__overflow(void )
{
}

# 235 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/Atm128UartP.nc"
static inline void /*Atm128Uart0C.UartP*/Atm128UartP__0__Counter__overflow(void )
#line 235
{
}

# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static void /*CounterMicro32C.Transform32*/TransformCounterC__1__Counter__overflow(void ){
#line 82
  /*Atm128Uart0C.UartP*/Atm128UartP__0__Counter__overflow();
#line 82
  /*LocalTimeMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__overflow();
#line 82
}
#line 82
# 133 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
static inline void /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__overflow(void )
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      /*CounterMicro32C.Transform32*/TransformCounterC__1__m_upper++;
      if ((/*CounterMicro32C.Transform32*/TransformCounterC__1__m_upper & /*CounterMicro32C.Transform32*/TransformCounterC__1__OVERFLOW_MASK) == 0) {
        /*CounterMicro32C.Transform32*/TransformCounterC__1__Counter__overflow();
        }
    }
#line 141
    __nesc_atomic_end(__nesc_atomic); }
}

# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static void /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__overflow(void ){
#line 82
  /*CounterMicro32C.Transform32*/TransformCounterC__1__CounterFrom__overflow();
#line 82
}
#line 82
# 65 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128CounterC.nc"
static inline void /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__overflow(void )
{
  /*CounterThree16C.NCounter*/Atm128CounterC__1__Counter__overflow();
}

# 60 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128TimerInitC.nc"
static inline void /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__overflow(void )
#line 60
{
}

# 70 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer.nc"
inline static void HplAtm128Timer3P__Timer__overflow(void ){
#line 70
  /*InitThreeP.InitThree*/Atm128TimerInitC__1__Timer__overflow();
#line 70
  /*CounterThree16C.NCounter*/Atm128CounterC__1__Timer__overflow();
#line 70
}
#line 70
# 238 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/Atm128UartP.nc"
static inline void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__default__receivedByte(uint8_t byte)
#line 238
{
}

# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
inline static void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__receivedByte(uint8_t byte){
#line 79
  /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__default__receivedByte(byte);
#line 79
}
#line 79
# 239 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/Atm128UartP.nc"
static inline void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__default__receiveDone(uint8_t *buf, uint16_t len, error_t error)
#line 239
{
}

# 99 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
inline static void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__receiveDone(uint8_t * buf, uint16_t len, error_t error){
#line 99
  /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__default__receiveDone(buf, len, error);
#line 99
}
#line 99
# 137 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/Atm128UartP.nc"
static inline void /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__rxDone(uint8_t data)
#line 137
{

  if (/*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_buf) {
      /*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_buf[/*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_pos++] = data;
      if (/*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_pos >= /*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_len) {
          uint8_t *buf = /*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_buf;

          /* atomic removed: atomic calls only */
#line 143
          {
            /*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_buf = (void *)0;
            if (/*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_intr != 3) {
                /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__disableRxIntr();
                /*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_intr = 0;
              }
          }
          /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__receiveDone(buf, /*Atm128Uart0C.UartP*/Atm128UartP__0__m_rx_len, SUCCESS);
        }
    }
  else {
      /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__receivedByte(data);
    }
}

# 49 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
inline static void HplAtm128UartP__HplUart0__rxDone(uint8_t data){
#line 49
  /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__rxDone(data);
#line 49
}
#line 49
# 237 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/Atm128UartP.nc"
static inline void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__default__sendDone(uint8_t *buf, uint16_t len, error_t error)
#line 237
{
}

# 57 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
inline static void /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__sendDone(uint8_t * buf, uint16_t len, error_t error){
#line 57
  /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__default__sendDone(buf, len, error);
#line 57
}
#line 57
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
inline static void /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__tx(uint8_t data){
#line 46
  HplAtm128UartP__HplUart0__tx(data);
#line 46
}
#line 46
# 177 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/Atm128UartP.nc"
static inline void /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__txDone(void )
#line 177
{

  if (/*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_pos < /*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_len) {
      /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__tx(/*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_buf[/*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_pos++]);
    }
  else {
      uint8_t *buf = /*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_buf;

#line 184
      /*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_buf = (void *)0;
      /*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_intr = 0;
      /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__disableTxIntr();
      /*Atm128Uart0C.UartP*/Atm128UartP__0__UartStream__sendDone(buf, /*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_len, SUCCESS);
    }
}

# 47 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
inline static void HplAtm128UartP__HplUart0__txDone(void ){
#line 47
  /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__txDone();
#line 47
}
#line 47
# 286 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128UartP.nc"
static inline void HplAtm128UartP__HplUart1__default__rxDone(uint8_t data)
#line 286
{
}

# 49 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
inline static void HplAtm128UartP__HplUart1__rxDone(uint8_t data){
#line 49
  HplAtm128UartP__HplUart1__default__rxDone(data);
#line 49
}
#line 49
# 285 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128UartP.nc"
static inline void HplAtm128UartP__HplUart1__default__txDone(void )
#line 285
{
}

# 47 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
inline static void HplAtm128UartP__HplUart1__txDone(void ){
#line 47
  HplAtm128UartP__HplUart1__default__txDone();
#line 47
}
#line 47
# 161 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128UartP.nc"
static inline bool HplAtm128UartP__HplUart0__isTxEmpty(void )
#line 161
{
  return (* (volatile uint8_t *)(0x0B + 0x20) & (1 << 6)) != 0;
}

# 44 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128Uart.nc"
inline static bool /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__isTxEmpty(void ){
#line 44
  unsigned char __nesc_result;
#line 44

#line 44
  __nesc_result = HplAtm128UartP__HplUart0__isTxEmpty();
#line 44

#line 44
  return __nesc_result;
#line 44
}
#line 44
# 192 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/Atm128UartP.nc"
static inline error_t /*Atm128Uart0C.UartP*/Atm128UartP__0__UartByte__send(uint8_t byte)
#line 192
{
  if (/*Atm128Uart0C.UartP*/Atm128UartP__0__m_tx_intr) {
    return FAIL;
    }
  /*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__tx(byte);
  while (!/*Atm128Uart0C.UartP*/Atm128UartP__0__HplUart__isTxEmpty()) ;
  return SUCCESS;
}

# 50 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartByte.nc"
inline static error_t SerialPrintfP__UartByte__send(uint8_t byte){
#line 50
  enum __nesc_unnamed4242 __nesc_result;
#line 50

#line 50
  __nesc_result = /*Atm128Uart0C.UartP*/Atm128UartP__0__UartByte__send(byte);
#line 50

#line 50
  return __nesc_result;
#line 50
}
#line 50
# 69 "/home/wtiberti/WSN/tinyos/tos/lib/printf/SerialPrintfP.nc"
static inline int SerialPrintfP__Putchar__putchar(int c)
{
  return SUCCESS == SerialPrintfP__UartByte__send(c) ? c : -1;
}

# 49 "/home/wtiberti/WSN/tinyos/tos/lib/printf/Putchar.nc"
inline static int PutcharP__Putchar__putchar(int c){
#line 49
  int __nesc_result;
#line 49

#line 49
  __nesc_result = SerialPrintfP__Putchar__putchar(c);
#line 49

#line 49
  return __nesc_result;
#line 49
}
#line 49
# 72 "/home/wtiberti/WSN/tinyos/tos/system/RealMainP.nc"
  int main(void )
#line 72
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 73
    {
#line 85
      {
      }
#line 85
      ;

      RealMainP__Scheduler__init();





      RealMainP__PlatformInit__init();
      while (RealMainP__Scheduler__runNextTask()) ;





      RealMainP__SoftwareInit__init();
      while (RealMainP__Scheduler__runNextTask()) ;
    }
#line 102
    __nesc_atomic_end(__nesc_atomic); }


  __nesc_enable_interrupt();

  RealMainP__Boot__booted();


  RealMainP__Scheduler__taskLoop();




  return -1;
}

# 202 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
static bool SchedulerBasicP__Scheduler__runNextTask(void )
#line 202
{
  /* atomic removed: atomic calls only */
#line 203
  {
    SchedulerBasicP__lastTask = SchedulerBasicP__popTask();
    if (SchedulerBasicP__lastTask == SchedulerBasicP__NO_TASK) 
      {
        unsigned char __nesc_temp = 
#line 206
        FALSE;

#line 206
        return __nesc_temp;
      }
  }
#line 208
  SchedulerBasicP__TaskBasic__runTask(SchedulerBasicP__lastTask);
  return TRUE;
}

#line 246
static void SchedulerBasicP__TaskBasic__default__runTask(uint8_t id)
#line 246
{
}

# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void SchedulerBasicP__TaskBasic__runTask(uint8_t arg_0x7f7cbb3d4de0){
#line 75
  switch (arg_0x7f7cbb3d4de0) {
#line 75
    case /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__fired:
#line 75
      /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__fired__runTask();
#line 75
      break;
#line 75
    case /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__updateFromTimer:
#line 75
      /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__updateFromTimer__runTask();
#line 75
      break;
#line 75
    case CC2420CsmaP__startDone_task:
#line 75
      CC2420CsmaP__startDone_task__runTask();
#line 75
      break;
#line 75
    case CC2420CsmaP__stopDone_task:
#line 75
      CC2420CsmaP__stopDone_task__runTask();
#line 75
      break;
#line 75
    case CC2420CsmaP__sendDone_task:
#line 75
      CC2420CsmaP__sendDone_task__runTask();
#line 75
      break;
#line 75
    case CC2420ControlP__sync:
#line 75
      CC2420ControlP__sync__runTask();
#line 75
      break;
#line 75
    case CC2420ControlP__syncDone:
#line 75
      CC2420ControlP__syncDone__runTask();
#line 75
      break;
#line 75
    case HplCC2420InterruptsP__CCATask:
#line 75
      HplCC2420InterruptsP__CCATask__runTask();
#line 75
      break;
#line 75
    case CC2420SpiP__grant:
#line 75
      CC2420SpiP__grant__runTask();
#line 75
      break;
#line 75
    case Atm128SpiP__zeroTask:
#line 75
      Atm128SpiP__zeroTask__runTask();
#line 75
      break;
#line 75
    case /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__grantedTask:
#line 75
      /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__grantedTask__runTask();
#line 75
      break;
#line 75
    case CC2420ReceiveP__receiveDone_task:
#line 75
      CC2420ReceiveP__receiveDone_task__runTask();
#line 75
      break;
#line 75
    case CC2420TinyosNetworkP__grantTask:
#line 75
      CC2420TinyosNetworkP__grantTask__runTask();
#line 75
      break;
#line 75
    case /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__CancelTask:
#line 75
      /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__CancelTask__runTask();
#line 75
      break;
#line 75
    case /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__errorTask:
#line 75
      /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__errorTask__runTask();
#line 75
      break;
#line 75
    default:
#line 75
      SchedulerBasicP__TaskBasic__default__runTask(arg_0x7f7cbb3d4de0);
#line 75
      break;
#line 75
    }
#line 75
}
#line 75
# 178 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__sendDone(uint8_t last, message_t * msg, error_t err)
#line 178
{
  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue[last].msg = (void *)0;
  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__tryToSend();
  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__sendDone(last, msg, err);
}

# 139 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static am_addr_t CC2420ActiveMessageP__AMPacket__destination(message_t *amsg)
#line 139
{
  cc2420_header_t *header = CC2420ActiveMessageP__CC2420PacketBody__getHeader(amsg);

#line 141
  return __nesc_ntoh_leuint16(header->dest.nxdata);
}

#line 87
static error_t CC2420ActiveMessageP__AMSend__send(am_id_t id, am_addr_t addr, 
message_t *msg, 
uint8_t len)
#line 89
{
  unsigned char *__nesc_temp48;
#line 90
  cc2420_header_t *header = CC2420ActiveMessageP__CC2420PacketBody__getHeader(msg);

  if (len > CC2420ActiveMessageP__Packet__maxPayloadLength()) {
      return ESIZE;
    }

  __nesc_hton_leuint8(header->type.nxdata, id);
  __nesc_hton_leuint16(header->dest.nxdata, addr);
  __nesc_hton_leuint16(header->destpan.nxdata, CC2420ActiveMessageP__CC2420Config__getPanAddr());
  __nesc_hton_leuint16(header->src.nxdata, CC2420ActiveMessageP__AMPacket__address());
  (__nesc_temp48 = header->fcf.nxdata, __nesc_hton_leuint16(__nesc_temp48, __nesc_ntoh_leuint16(__nesc_temp48) | (((1 << IEEE154_FCF_INTRAPAN) | (
  IEEE154_ADDR_SHORT << IEEE154_FCF_DEST_ADDR_MODE)) | (
  IEEE154_ADDR_SHORT << IEEE154_FCF_SRC_ADDR_MODE))));
  __nesc_hton_leuint8(header->length.nxdata, len + CC2420_SIZE);

  if (CC2420ActiveMessageP__RadioResource__immediateRequest() == SUCCESS) {
      error_t rc;

#line 107
      CC2420ActiveMessageP__SendNotifier__aboutToSend(id, addr, msg);

      rc = CC2420ActiveMessageP__SubSend__send(msg, len);
      if (rc != SUCCESS) {
          CC2420ActiveMessageP__RadioResource__release();
        }

      return rc;
    }
  else 
#line 115
    {
      CC2420ActiveMessageP__pending_length = len;
      CC2420ActiveMessageP__pending_message = msg;
      return CC2420ActiveMessageP__RadioResource__request();
    }
}

# 120 "/home/wtiberti/WSN/tinyos/tos/system/ActiveMessageAddressC.nc"
static am_addr_t ActiveMessageAddressC__amAddress(void )
#line 120
{
  am_addr_t myAddr;

#line 122
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 122
    myAddr = ActiveMessageAddressC__addr;
#line 122
    __nesc_atomic_end(__nesc_atomic); }
  return myAddr;
}

# 60 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
static bool /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__FcfsQueue__isEmpty(void )
#line 60
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 61
    {
      unsigned char __nesc_temp = 
#line 61
      /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__qHead == /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0__NO_ENTRY;

      {
#line 61
        __nesc_atomic_end(__nesc_atomic); 
#line 61
        return __nesc_temp;
      }
    }
#line 63
    __nesc_atomic_end(__nesc_atomic); }
}

# 80 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
static error_t CC2420TinyosNetworkP__ActiveSend__send(message_t *msg, uint8_t len)
#line 80
{
  CC2420TinyosNetworkP__CC2420Packet__setNetwork(msg, 0x3f);
  CC2420TinyosNetworkP__m_busy_client = CC2420TinyosNetworkP__CLIENT_AM;
  return CC2420TinyosNetworkP__SubSend__send(msg, len);
}

# 90 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/packet/CC2420PacketP.nc"
static uint8_t * CC2420PacketP__getNetwork(message_t * msg)
#line 90
{
  cc2420_header_t *hdr = CC2420PacketP__CC2420PacketBody__getHeader(msg);
  int offset;

  offset = CC2420PacketP__getAddressLength((__nesc_ntoh_leuint16(hdr->fcf.nxdata) >> IEEE154_FCF_DEST_ADDR_MODE) & 0x3) + 
  CC2420PacketP__getAddressLength((__nesc_ntoh_leuint16(hdr->fcf.nxdata) >> IEEE154_FCF_SRC_ADDR_MODE) & 0x3) + 
  (unsigned short )& ((cc2420_header_t *)0)->dest;

  return (uint8_t *)hdr + offset;
}

# 96 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
static error_t StateImplP__State__requestState(uint8_t id, uint8_t reqState)
#line 96
{
  error_t returnVal = FAIL;

#line 98
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 98
    {
      if (reqState == StateImplP__S_IDLE || StateImplP__state[id] == StateImplP__S_IDLE) {
          StateImplP__state[id] = reqState;
          returnVal = SUCCESS;
        }
    }
#line 103
    __nesc_atomic_end(__nesc_atomic); }
  return returnVal;
}

#line 133
static bool StateImplP__State__isState(uint8_t id, uint8_t myState)
#line 133
{
  bool isState;

#line 135
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 135
    isState = StateImplP__state[id] == myState;
#line 135
    __nesc_atomic_end(__nesc_atomic); }
  return isState;
}

# 795 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static error_t CC2420TransmitP__acquireSpiResource(void )
#line 795
{
  error_t error = CC2420TransmitP__SpiResource__immediateRequest();

#line 797
  if (error != SUCCESS) {
      CC2420TransmitP__SpiResource__request();
    }
  return error;
}

# 126 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static error_t CC2420SpiP__Resource__immediateRequest(uint8_t id)
#line 126
{
  error_t error;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 129
    {
      if (CC2420SpiP__WorkingState__requestState(CC2420SpiP__S_BUSY) != SUCCESS) {
          {
            enum __nesc_unnamed4242 __nesc_temp = 
#line 131
            EBUSY;

            {
#line 131
              __nesc_atomic_end(__nesc_atomic); 
#line 131
              return __nesc_temp;
            }
          }
        }
      if (CC2420SpiP__SpiResource__isOwner()) {
          CC2420SpiP__m_holder = id;
          error = SUCCESS;
        }
      else {
#line 139
        if ((error = CC2420SpiP__SpiResource__immediateRequest()) == SUCCESS) {
            CC2420SpiP__m_holder = id;
          }
        else {
            CC2420SpiP__WorkingState__toIdle();
          }
        }
    }
#line 146
    __nesc_atomic_end(__nesc_atomic); }
#line 146
  return error;
}

# 137 "/home/wtiberti/WSN/tinyos/tos/system/SimpleArbiterP.nc"
static bool /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__Resource__isOwner(uint8_t id)
#line 137
{
  /* atomic removed: atomic calls only */
#line 138
  {
    if (/*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__resId == id && /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__state == /*Atm128SpiC.Arbiter.Arbiter*/SimpleArbiterP__0__RES_BUSY) {
        unsigned char __nesc_temp = 
#line 139
        TRUE;

#line 139
        return __nesc_temp;
      }
    else 
#line 140
      {
        unsigned char __nesc_temp = 
#line 140
        FALSE;

#line 140
        return __nesc_temp;
      }
  }
}

# 129 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128SpiP.nc"
static void Atm128SpiP__startSpi(void )
#line 129
{
  Atm128SpiP__Spi__enableSpi(FALSE);
  /* atomic removed: atomic calls only */
#line 131
  {
    Atm128SpiP__Spi__initMaster();
    Atm128SpiP__Spi__enableInterrupt(FALSE);
    Atm128SpiP__Spi__setClockPolarity(FALSE);
    Atm128SpiP__Spi__setClockPhase(FALSE);
    Atm128SpiP__Spi__enableSpi(TRUE);
#line 158
    Atm128SpiP__Spi__setMasterDoubleSpeed(TRUE);
    Atm128SpiP__Spi__setClock(0);
  }

  Atm128SpiP__McuPowerState__update();
}

# 147 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
static void HplAtm128SpiP__SPI__enableSpi(bool enabled)
#line 147
{
  if (enabled) {
      * (volatile uint8_t *)(0x0D + 0x20) |= 1 << 6;
      HplAtm128SpiP__Mcu__update();
    }
  else {
      * (volatile uint8_t *)(0x0D + 0x20) &= ~(1 << 6);
      HplAtm128SpiP__Mcu__update();
    }
}

#line 132
static void HplAtm128SpiP__SPI__enableInterrupt(bool enabled)
#line 132
{
  if (enabled) {
      * (volatile uint8_t *)(0x0D + 0x20) |= 1 << 7;
      HplAtm128SpiP__Mcu__update();
    }
  else {
      * (volatile uint8_t *)(0x0D + 0x20) &= ~(1 << 7);
      HplAtm128SpiP__Mcu__update();
    }
}

# 107 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static error_t CC2420SpiP__Resource__request(uint8_t id)
#line 107
{

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 109
    {
      if (CC2420SpiP__WorkingState__requestState(CC2420SpiP__S_BUSY) == SUCCESS) {
          CC2420SpiP__m_holder = id;
          if (CC2420SpiP__SpiResource__isOwner()) {
              CC2420SpiP__grant__postTask();
            }
          else {
              CC2420SpiP__SpiResource__request();
            }
        }
      else {
          CC2420SpiP__m_requests |= 1 << id;
        }
    }
#line 122
    __nesc_atomic_end(__nesc_atomic); }
  return SUCCESS;
}

# 236 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
static error_t SchedulerBasicP__TaskBasic__postTask(uint8_t id)
#line 236
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 237
    {
      if (SchedulerBasicP__pushTask(id)) {
          SchedulerBasicP__trace_post_task(id);
          {
            enum __nesc_unnamed4242 __nesc_temp = 
#line 240
            SUCCESS;

            {
#line 240
              __nesc_atomic_end(__nesc_atomic); 
#line 240
              return __nesc_temp;
            }
          }
        }
      else 
#line 242
        {
          enum __nesc_unnamed4242 __nesc_temp = 
#line 242
          EBUSY;

          {
#line 242
            __nesc_atomic_end(__nesc_atomic); 
#line 242
            return __nesc_temp;
          }
        }
    }
#line 245
    __nesc_atomic_end(__nesc_atomic); }
}

# 825 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static void CC2420TransmitP__loadTXFIFO(void )
#line 825
{
  cc2420_header_t *header = CC2420TransmitP__CC2420PacketBody__getHeader(CC2420TransmitP__m_msg);
  uint8_t tx_power = __nesc_ntoh_uint8(CC2420TransmitP__CC2420PacketBody__getMetadata(CC2420TransmitP__m_msg)->tx_power.nxdata);

  if (!tx_power) {
      tx_power = 31;
    }

  CC2420TransmitP__CSN__clr();

  if (CC2420TransmitP__m_tx_power != tx_power) {
      CC2420TransmitP__TXCTRL__write((((2 << CC2420_TXCTRL_TXMIXBUF_CUR) | (
      3 << CC2420_TXCTRL_PA_CURRENT)) | (
      1 << CC2420_TXCTRL_RESERVED)) | ((
      tx_power & 0x1F) << CC2420_TXCTRL_PA_LEVEL));
    }

  CC2420TransmitP__m_tx_power = tx_power;

  {
    uint8_t tmpLen __attribute((unused))  = __nesc_ntoh_leuint8(header->length.nxdata) - 1;

#line 846
    CC2420TransmitP__TXFIFO__write((uint8_t * )header, __nesc_ntoh_leuint8(header->length.nxdata) - 1);
  }
}

# 305 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static cc2420_status_t CC2420SpiP__Reg__write(uint8_t addr, uint16_t data)
#line 305
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 306
    {
      if (CC2420SpiP__WorkingState__isIdle()) {
          {
            unsigned char __nesc_temp = 
#line 308
            0;

            {
#line 308
              __nesc_atomic_end(__nesc_atomic); 
#line 308
              return __nesc_temp;
            }
          }
        }
    }
#line 312
    __nesc_atomic_end(__nesc_atomic); }
#line 311
  CC2420SpiP__SpiByte__write(addr);
  CC2420SpiP__SpiByte__write(data >> 8);
  return CC2420SpiP__SpiByte__write(data & 0xff);
}

# 173 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/Atm128SpiP.nc"
static uint8_t Atm128SpiP__SpiByte__write(uint8_t tx)
#line 173
{






  Atm128SpiP__Spi__enableSpi(TRUE);
  Atm128SpiP__McuPowerState__update();


  Atm128SpiP__Spi__write(tx);

  while (!Atm128SpiP__Spi__isInterruptPending()) 
    ;

  return Atm128SpiP__Spi__read();
}

#line 328
static error_t Atm128SpiP__SpiPacket__send(uint8_t *writeBuf, 
uint8_t *readBuf, 
uint16_t bufLen)
#line 330
{
  uint8_t discard;

#line 332
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 332
    {
      Atm128SpiP__len = bufLen;
      Atm128SpiP__txBuffer = writeBuf;
      Atm128SpiP__rxBuffer = readBuf;
      Atm128SpiP__pos = 0;
    }
#line 337
    __nesc_atomic_end(__nesc_atomic); }
  if (bufLen > 0) {
      discard = Atm128SpiP__Spi__read();
      return Atm128SpiP__sendNextPart();
    }
  else {
      Atm128SpiP__zeroTask__postTask();
      return SUCCESS;
    }
}

#line 249
static error_t Atm128SpiP__sendNextPart(void )
#line 249
{
  uint16_t end;
  uint16_t tmpPos;
  uint16_t myLen;
  uint8_t * tx;
  uint8_t * rx;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 256
    {
      myLen = Atm128SpiP__len;
      tx = Atm128SpiP__txBuffer;
      rx = Atm128SpiP__rxBuffer;
      tmpPos = Atm128SpiP__pos;
      end = Atm128SpiP__pos + Atm128SpiP__SPI_ATOMIC_SIZE;
      end = end > Atm128SpiP__len ? Atm128SpiP__len : end;
    }
#line 263
    __nesc_atomic_end(__nesc_atomic); }

  for (; tmpPos < end - 1; tmpPos++) {
      uint8_t val;

#line 267
      if (tx != (void *)0) {
        val = Atm128SpiP__SpiByte__write(tx[tmpPos]);
        }
      else {
#line 270
        val = Atm128SpiP__SpiByte__write(0);
        }
      if (rx != (void *)0) {
          rx[tmpPos] = val;
        }
    }



  Atm128SpiP__Spi__enableInterrupt(TRUE);
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 280
    {
      if (tx != (void *)0) {
        Atm128SpiP__Spi__write(tx[tmpPos]);
        }
      else {
#line 284
        Atm128SpiP__Spi__write(0);
        }
      Atm128SpiP__pos = tmpPos;
    }
#line 287
    __nesc_atomic_end(__nesc_atomic); }


  return SUCCESS;
}

# 56 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
static void UniqueSendP__State__toIdle(void ){
#line 56
  StateImplP__State__toIdle(2U);
#line 56
}
#line 56
# 74 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
static void CC2420ActiveMessageP__RadioResource__granted(void )
#line 74
{
  uint8_t rc;
  cc2420_header_t *header = CC2420ActiveMessageP__CC2420PacketBody__getHeader(CC2420ActiveMessageP__pending_message);

  CC2420ActiveMessageP__SendNotifier__aboutToSend(__nesc_ntoh_leuint8(header->type.nxdata), __nesc_ntoh_leuint16(header->dest.nxdata), CC2420ActiveMessageP__pending_message);
  rc = CC2420ActiveMessageP__SubSend__send(CC2420ActiveMessageP__pending_message, CC2420ActiveMessageP__pending_length);
  if (rc != SUCCESS) {
      CC2420ActiveMessageP__RadioResource__release();
      CC2420ActiveMessageP__AMSend__sendDone(__nesc_ntoh_leuint8(header->type.nxdata), CC2420ActiveMessageP__pending_message, rc);
    }
}

# 204 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMSend__sendDone(am_id_t id, message_t *msg, error_t err)
#line 204
{





  if (/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current >= 1) {
      return;
    }
  if (/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__queue[/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current].msg == msg) {
      /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__sendDone(/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__current, msg, err);
    }
  else {
      ;
    }
}

# 302 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static uint16_t CC2420ControlP__CC2420Config__getShortAddr(void )
#line 302
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 303
    {
      unsigned short __nesc_temp = 
#line 303
      CC2420ControlP__m_short_addr;

      {
#line 303
        __nesc_atomic_end(__nesc_atomic); 
#line 303
        return __nesc_temp;
      }
    }
#line 305
    __nesc_atomic_end(__nesc_atomic); }
}

# 180 "../TAKSM.nc"
static void TAKSM__vector_mult(uint8_t *out_ss, uint8_t *c1, uint8_t *c2)
{
  int i;
  uint8_t *ss = out_ss;
  uint8_t *p1x = c1;
  uint8_t *p1y = TAKSM__tc_getY(c1);
  uint8_t *p2x = c2;
  uint8_t *p2y = TAKSM__tc_getY(c2);

#line 188
  for (i = 0; i < 16; ++i) {
      ss[i] = TAKSM__galois_mult(p1x[i], p2x[i]) ^ TAKSM__galois_mult(p1y[i], p2y[i]);
    }
}

#line 160
static uint8_t TAKSM__galois_mult(uint8_t a, uint8_t b)
{
  uint8_t p = 0;

#line 163
  while (a && b) {
      if (b & 1) {
#line 164
        p ^= a;
        }
#line 165
      if (a & 0x80) {
#line 165
        a = (a << 1) ^ 0x11B;
        }
      else {
#line 166
        a <<= 1;
        }
#line 167
      b >>= 1;
    }
  return p;
}

#line 221
static void TAKSM__authentication_tag(uint8_t *out, const uint8_t *in, size_t size, uint8_t *k)
{



  int i;
  uint8_t checksum = 0;

#line 228
  for (i = 0; i < size; ++i) {
#line 228
      checksum += in[i];
    }
#line 229
  for (i = 0; i < 16; ++i) {
#line 229
      checksum += k[i];
    }
#line 230
  for (i = 0; i < 4; ++i) {
#line 230
      out[i] = checksum;
    }
}

# 769 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static void CC2420ReceiveP__waitForNextPacket(void )
#line 769
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 770
    {
      if (CC2420ReceiveP__m_state == CC2420ReceiveP__S_STOPPED) {
          CC2420ReceiveP__SpiResource__release();
          {
#line 773
            __nesc_atomic_end(__nesc_atomic); 
#line 773
            return;
          }
        }
      CC2420ReceiveP__receivingPacket = FALSE;
#line 788
      if ((CC2420ReceiveP__m_missed_packets && CC2420ReceiveP__FIFO__get()) || !CC2420ReceiveP__FIFOP__get()) {

          if (CC2420ReceiveP__m_missed_packets) {
              CC2420ReceiveP__m_missed_packets--;
            }





          CC2420ReceiveP__beginReceive();
        }
      else 
        {

          CC2420ReceiveP__m_state = CC2420ReceiveP__S_STARTED;
          CC2420ReceiveP__m_missed_packets = 0;
          CC2420ReceiveP__SpiResource__release();
        }
    }
#line 807
    __nesc_atomic_end(__nesc_atomic); }
}

# 149 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static error_t CC2420SpiP__Resource__release(uint8_t id)
#line 149
{
  uint8_t i;

#line 151
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 151
    {
      if (CC2420SpiP__m_holder != id) {
          {
            enum __nesc_unnamed4242 __nesc_temp = 
#line 153
            FAIL;

            {
#line 153
              __nesc_atomic_end(__nesc_atomic); 
#line 153
              return __nesc_temp;
            }
          }
        }
#line 156
      CC2420SpiP__m_holder = CC2420SpiP__NO_HOLDER;
      if (!CC2420SpiP__m_requests) {
          CC2420SpiP__WorkingState__toIdle();
          CC2420SpiP__attemptRelease();
        }
      else {
          for (i = CC2420SpiP__m_holder + 1; ; i++) {
              i %= CC2420SpiP__RESOURCE_COUNT;

              if (CC2420SpiP__m_requests & (1 << i)) {
                  CC2420SpiP__m_holder = i;
                  CC2420SpiP__m_requests &= ~(1 << i);
                  CC2420SpiP__grant__postTask();
                  {
                    enum __nesc_unnamed4242 __nesc_temp = 
#line 169
                    SUCCESS;

                    {
#line 169
                      __nesc_atomic_end(__nesc_atomic); 
#line 169
                      return __nesc_temp;
                    }
                  }
                }
            }
        }
    }
#line 175
    __nesc_atomic_end(__nesc_atomic); }
#line 175
  return SUCCESS;
}

#line 339
static error_t CC2420SpiP__attemptRelease(void )
#line 339
{


  if ((
#line 340
  CC2420SpiP__m_requests > 0
   || CC2420SpiP__m_holder != CC2420SpiP__NO_HOLDER)
   || !CC2420SpiP__WorkingState__isIdle()) {
      return FAIL;
    }
  /* atomic removed: atomic calls only */
  CC2420SpiP__release = TRUE;
  CC2420SpiP__ChipSpiResource__releasing();
  /* atomic removed: atomic calls only */
#line 348
  {
    if (CC2420SpiP__release) {
        CC2420SpiP__SpiResource__release();
        {
          enum __nesc_unnamed4242 __nesc_temp = 
#line 351
          SUCCESS;

#line 351
          return __nesc_temp;
        }
      }
  }
  return EBUSY;
}

# 716 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static void CC2420ReceiveP__beginReceive(void )
#line 716
{
  CC2420ReceiveP__m_state = CC2420ReceiveP__S_RX_LENGTH;
  /* atomic removed: atomic calls only */
#line 718
  CC2420ReceiveP__receivingPacket = TRUE;
  if (CC2420ReceiveP__SpiResource__isOwner()) {
      CC2420ReceiveP__receive();
    }
  else {
#line 722
    if (CC2420ReceiveP__SpiResource__immediateRequest() == SUCCESS) {
        CC2420ReceiveP__receive();
      }
    else {
        CC2420ReceiveP__SpiResource__request();
      }
    }
}

#line 759
static void CC2420ReceiveP__receive(void )
#line 759
{
  CC2420ReceiveP__CSN__clr();
  CC2420ReceiveP__RXFIFO__beginRead((uint8_t *)CC2420ReceiveP__CC2420PacketBody__getHeader(CC2420ReceiveP__m_p_rx_buf), 1);
}

# 189 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static cc2420_status_t CC2420SpiP__Fifo__beginRead(uint8_t addr, uint8_t *data, 
uint8_t len)
#line 190
{

  cc2420_status_t status = 0;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 194
    {
      if (CC2420SpiP__WorkingState__isIdle()) {
          {
            unsigned char __nesc_temp = 
#line 196
            status;

            {
#line 196
              __nesc_atomic_end(__nesc_atomic); 
#line 196
              return __nesc_temp;
            }
          }
        }
    }
#line 200
    __nesc_atomic_end(__nesc_atomic); }
#line 200
  CC2420SpiP__m_addr = addr | 0x40;

  status = CC2420SpiP__SpiByte__write(CC2420SpiP__m_addr);
  CC2420SpiP__Fifo__continueRead(addr, data, len);

  return status;
}

#line 329
static void CC2420SpiP__SpiPacket__sendDone(uint8_t *tx_buf, uint8_t *rx_buf, 
uint16_t len, error_t error)
#line 330
{
  if (CC2420SpiP__m_addr & 0x40) {
      CC2420SpiP__Fifo__readDone(CC2420SpiP__m_addr & ~0x40, rx_buf, len, error);
    }
  else 
#line 333
    {
      CC2420SpiP__Fifo__writeDone(CC2420SpiP__m_addr, tx_buf, len, error);
    }
}

# 733 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/receive/CC2420ReceiveP.nc"
static void CC2420ReceiveP__flush(void )
#line 733
{








  CC2420ReceiveP__reset_state();

  CC2420ReceiveP__CSN__set();
  CC2420ReceiveP__CSN__clr();
  CC2420ReceiveP__SFLUSHRX__strobe();
  CC2420ReceiveP__SFLUSHRX__strobe();
  CC2420ReceiveP__CSN__set();
  CC2420ReceiveP__SpiResource__release();
  CC2420ReceiveP__waitForNextPacket();
}

#line 813
static void CC2420ReceiveP__reset_state(void )
#line 813
{
  CC2420ReceiveP__m_bytes_left = CC2420ReceiveP__RXFIFO_SIZE;
  /* atomic removed: atomic calls only */
#line 815
  CC2420ReceiveP__receivingPacket = FALSE;
  CC2420ReceiveP__m_timestamp_head = 0;
  CC2420ReceiveP__m_timestamp_size = 0;
  CC2420ReceiveP__m_missed_packets = 0;
}

# 318 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static cc2420_status_t CC2420SpiP__Strobe__strobe(uint8_t addr)
#line 318
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 319
    {
      if (CC2420SpiP__WorkingState__isIdle()) {
          {
            unsigned char __nesc_temp = 
#line 321
            0;

            {
#line 321
              __nesc_atomic_end(__nesc_atomic); 
#line 321
              return __nesc_temp;
            }
          }
        }
    }
#line 325
    __nesc_atomic_end(__nesc_atomic); }
#line 325
  return CC2420SpiP__SpiByte__write(addr);
}

# 171 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/packet/CC2420PacketP.nc"
static void CC2420PacketP__PacketTimeStamp32khz__clear(message_t *msg)
{
  __nesc_hton_int8(CC2420PacketP__CC2420PacketBody__getMetadata(msg)->timesync.nxdata, FALSE);
  __nesc_hton_uint32(CC2420PacketP__CC2420PacketBody__getMetadata(msg)->timestamp.nxdata, CC2420_INVALID_TIMESTAMP);
}

static void CC2420PacketP__PacketTimeStamp32khz__set(message_t *msg, uint32_t value)
{
  __nesc_hton_uint32(CC2420PacketP__CC2420PacketBody__getMetadata(msg)->timestamp.nxdata, value);
}

# 850 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/transmit/CC2420TransmitP.nc"
static void CC2420TransmitP__signalDone(error_t err)
#line 850
{
  /* atomic removed: atomic calls only */
#line 851
  CC2420TransmitP__m_state = CC2420TransmitP__S_STARTED;
  CC2420TransmitP__abortSpiRelease = FALSE;
  CC2420TransmitP__ChipSpiResource__attemptRelease();
  CC2420TransmitP__Send__sendDone(CC2420TransmitP__m_msg, err);
}

#line 743
static void CC2420TransmitP__attemptSend(void )
#line 743
{
  uint8_t status;
  bool congestion = TRUE;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 747
    {
      if (CC2420TransmitP__m_state == CC2420TransmitP__S_CANCEL) {
          CC2420TransmitP__SFLUSHTX__strobe();
          CC2420TransmitP__releaseSpiResource();
          CC2420TransmitP__CSN__set();
          CC2420TransmitP__m_state = CC2420TransmitP__S_STARTED;
          CC2420TransmitP__Send__sendDone(CC2420TransmitP__m_msg, ECANCEL);
          {
#line 754
            __nesc_atomic_end(__nesc_atomic); 
#line 754
            return;
          }
        }





      CC2420TransmitP__CSN__clr();
      status = CC2420TransmitP__m_cca ? CC2420TransmitP__STXONCCA__strobe() : CC2420TransmitP__STXON__strobe();
      if (!(status & CC2420_STATUS_TX_ACTIVE)) {
          status = CC2420TransmitP__SNOP__strobe();
          if (status & CC2420_STATUS_TX_ACTIVE) {
              congestion = FALSE;
            }
        }

      CC2420TransmitP__m_state = congestion ? CC2420TransmitP__S_SAMPLE_CCA : CC2420TransmitP__S_SFD;
      CC2420TransmitP__CSN__set();
    }
#line 773
    __nesc_atomic_end(__nesc_atomic); }

  if (congestion) {
      CC2420TransmitP__totalCcaChecks = 0;
      CC2420TransmitP__releaseSpiResource();
      CC2420TransmitP__congestionBackoff();
    }
  else 
#line 779
    {
      CC2420TransmitP__BackoffTimer__start(CC2420TransmitP__CC2420_ABORT_PERIOD);
    }
}





static void CC2420TransmitP__congestionBackoff(void )
#line 788
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 789
    {
      CC2420TransmitP__RadioBackoff__requestCongestionBackoff(CC2420TransmitP__m_msg);
      CC2420TransmitP__BackoffTimer__start(CC2420TransmitP__myCongestionBackoff);
    }
#line 792
    __nesc_atomic_end(__nesc_atomic); }
}

# 69 "/home/wtiberti/WSN/tinyos/tos/system/RandomMlcgC.nc"
static uint32_t RandomMlcgC__Random__rand32(void )
#line 69
{
  uint32_t mlcg;
#line 70
  uint32_t p;
#line 70
  uint32_t q;
  uint64_t tmpseed;

  /* atomic removed: atomic calls only */
#line 73
  {
    tmpseed = (uint64_t )33614U * (uint64_t )RandomMlcgC__seed;
    q = tmpseed;
    q = q >> 1;
    p = tmpseed >> 32;
    mlcg = p + q;
    if (mlcg & 0x80000000) {
        mlcg = mlcg & 0x7FFFFFFF;
        mlcg++;
      }
    RandomMlcgC__seed = mlcg;
  }
  return mlcg;
}

# 147 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Alarm__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type dt)
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_t0 = t0;
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_dt = dt;
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__set_alarm();
    }
#line 154
    __nesc_atomic_end(__nesc_atomic); }
}

#line 107
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__set_alarm(void )
{
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type now = /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__Counter__get();
#line 109
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type expires;
#line 109
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type remaining;




  expires = /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_t0 + /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_dt;


  remaining = (/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__to_size_type )(expires - now);


  if (/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_t0 <= now) 
    {
      if (expires >= /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_t0 && 
      expires <= now) {
        remaining = 0;
        }
    }
  else {
      if (expires >= /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_t0 || 
      expires <= now) {
        remaining = 0;
        }
    }
#line 132
  if (remaining > /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__MAX_DELAY) 
    {
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_t0 = now + /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__MAX_DELAY;
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_dt = remaining - /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__MAX_DELAY;
      remaining = /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__MAX_DELAY;
    }
  else 
    {
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_t0 += /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_dt;
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__m_dt = 0;
    }
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__AlarmFrom__startAt((/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__from_size_type )now << 0, 
  (/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform32*/TransformAlarmC__0__from_size_type )remaining << 0);
}

# 80 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
static /*Counter32khz32C.Transform32*/TransformCounterC__0__to_size_type /*Counter32khz32C.Transform32*/TransformCounterC__0__Counter__get(void )
{
  /*Counter32khz32C.Transform32*/TransformCounterC__0__to_size_type rv = 0;

#line 83
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      /*Counter32khz32C.Transform32*/TransformCounterC__0__upper_count_type high = /*Counter32khz32C.Transform32*/TransformCounterC__0__m_upper;
      /*Counter32khz32C.Transform32*/TransformCounterC__0__from_size_type low = /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__get();

#line 87
      if (/*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__isOverflowPending()) 
        {






          high++;
          low = /*Counter32khz32C.Transform32*/TransformCounterC__0__CounterFrom__get();
        }
      {
        /*Counter32khz32C.Transform32*/TransformCounterC__0__to_size_type high_to = high;
        /*Counter32khz32C.Transform32*/TransformCounterC__0__to_size_type low_to = low >> /*Counter32khz32C.Transform32*/TransformCounterC__0__LOW_SHIFT_RIGHT;

#line 101
        rv = (high_to << /*Counter32khz32C.Transform32*/TransformCounterC__0__HIGH_SHIFT_LEFT) | low_to;
      }
    }
#line 103
    __nesc_atomic_end(__nesc_atomic); }
  return rv;
}

# 479 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/control/CC2420ControlP.nc"
static void CC2420ControlP__writeFsctrl(void )
#line 479
{
  uint8_t channel;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 482
    {
      channel = CC2420ControlP__m_channel;
    }
#line 484
    __nesc_atomic_end(__nesc_atomic); }

  CC2420ControlP__FSCTRL__write((1 << CC2420_FSCTRL_LOCK_THR) | (((
  channel - 11) * 5 + 357) << CC2420_FSCTRL_FREQ));
}







static void CC2420ControlP__writeMdmctrl0(void )
#line 496
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 497
    {
      CC2420ControlP__MDMCTRL0__write((((((((1 << CC2420_MDMCTRL0_RESERVED_FRAME_MODE) | ((
      CC2420ControlP__addressRecognition && CC2420ControlP__hwAddressRecognition ? 1 : 0) << CC2420_MDMCTRL0_ADR_DECODE)) | (
      2 << CC2420_MDMCTRL0_CCA_HYST)) | (
      3 << CC2420_MDMCTRL0_CCA_MOD)) | (
      1 << CC2420_MDMCTRL0_AUTOCRC)) | ((
      CC2420ControlP__autoAckEnabled && CC2420ControlP__hwAutoAckDefault) << CC2420_MDMCTRL0_AUTOACK)) | (
      0 << CC2420_MDMCTRL0_AUTOACK)) | (
      2 << CC2420_MDMCTRL0_PREAMBLE_LENGTH));
    }
#line 506
    __nesc_atomic_end(__nesc_atomic); }
}







static void CC2420ControlP__writeId(void )
#line 515
{
  nxle_uint16_t id[6];

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 518
    {

      memcpy((uint8_t *)id, CC2420ControlP__m_ext_addr.data, 8);
      __nesc_hton_leuint16(id[4].nxdata, CC2420ControlP__m_pan);
      __nesc_hton_leuint16(id[5].nxdata, CC2420ControlP__m_short_addr);
    }
#line 523
    __nesc_atomic_end(__nesc_atomic); }

  CC2420ControlP__IEEEADR__write(0, (uint8_t *)&id, 12);
}

# 260 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
static cc2420_status_t CC2420SpiP__Ram__write(uint16_t addr, uint8_t offset, 
uint8_t *data, 
uint8_t len)
#line 262
{

  cc2420_status_t status = 0;
  uint8_t tmpLen = len;
  uint8_t * tmpData = (uint8_t * )data;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 268
    {
      if (CC2420SpiP__WorkingState__isIdle()) {
          {
            unsigned char __nesc_temp = 
#line 270
            status;

            {
#line 270
              __nesc_atomic_end(__nesc_atomic); 
#line 270
              return __nesc_temp;
            }
          }
        }
    }
#line 274
    __nesc_atomic_end(__nesc_atomic); }
#line 274
  addr += offset;

  status = CC2420SpiP__SpiByte__write(addr | 0x80);
  CC2420SpiP__SpiByte__write((addr >> 1) & 0xc0);
  for (; len; len--) {
      CC2420SpiP__SpiByte__write(tmpData[tmpLen - len]);
    }

  return status;
}

# 49 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128GpioCaptureC.nc"
static error_t /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__enableCapture(uint8_t mode)
#line 49
{
  /* atomic removed: atomic calls only */
#line 50
  {
    /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__stop();
    /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__reset();
    /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__setEdge(mode);
    /*HplCC2420InterruptsC.CaptureSFDC*/Atm128GpioCaptureC__0__Atm128Capture__start();
  }
  return SUCCESS;
}

# 161 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmAsyncP.nc"
static uint32_t /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Counter__get(void )
#line 161
{
  uint32_t now;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {


      uint8_t now8 = /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__get();

      if (/*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerCtrl__getInterruptFlag().bits.ocf0) {


        now = /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__base + /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__get() + 1 + /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__get();
        }
      else {

        now = /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__base + now8;
        }
    }
#line 179
    __nesc_atomic_end(__nesc_atomic); }
#line 179
  return now;
}

# 81 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/csma/CC2420CsmaP.nc"
static error_t CC2420CsmaP__SplitControl__start(void )
#line 81
{
  if (CC2420CsmaP__SplitControlState__requestState(CC2420CsmaP__S_STARTING) == SUCCESS) {
      CC2420CsmaP__CC2420Power__startVReg();
      return SUCCESS;
    }
  else {
#line 86
    if (CC2420CsmaP__SplitControlState__isState(CC2420CsmaP__S_STARTED)) {
        return EALREADY;
      }
    else {
#line 89
      if (CC2420CsmaP__SplitControlState__isState(CC2420CsmaP__S_STARTING)) {
          return SUCCESS;
        }
      }
    }
#line 93
  return EBUSY;
}

# 155 "/home/wtiberti/WSN/tinyos/tos/lib/timer/VirtualizeTimerImplP.nc"
static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__fireTimers(uint32_t now)
#line 155
{
  uint16_t num;
  uint32_t delta;

  for (num = 0; num < /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__NUM_TIMERS; num++) {
      /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer_t *timer = &/*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__m_timers[num];

      if (timer->isrunning) {
          uint32_t elapsed = now - timer->t0;

          if (elapsed >= timer->dt) {
              if (timer->isoneshot) {
                timer->isrunning = FALSE;
                }
              else {
#line 169
                timer->t0 += timer->dt;
                }
              /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__trace_timer_fired(num);
              delta = /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Platform__usecsRaw();

              /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__fired(num);
              delta = /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Platform__usecsRaw() - delta;
              /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__trace_timer_end(num, delta);
              break;
            }
        }
    }
  /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__updateFromTimer__postTask();
}

# 94 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
static void *CC2420TinyosNetworkP__ActiveSend__getPayload(message_t *msg, uint8_t len)
#line 94
{
  if (len <= CC2420TinyosNetworkP__ActiveSend__maxPayloadLength()) {
      return msg->data;
    }
  else 
#line 97
    {
      return (void *)0;
    }
}

# 172 "../TAKSM.nc"
static void TAKSM__elementwise_mult(uint8_t *out, uint8_t *c1, uint8_t *c2)
{
  int i;

#line 175
  for (i = 0; i < 16 * 2; ++i) {
      out[i] = TAKSM__galois_mult(c1[i], c2[i]);
    }
}

# 212 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/Atm128AlarmAsyncP.nc"
static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__startAt(uint32_t nt0, uint32_t ndt)
#line 212
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__set = TRUE;
      /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__t0 = nt0;
      /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__dt = ndt;
    }
#line 218
    __nesc_atomic_end(__nesc_atomic); }
  /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__setInterrupt();
}

#line 90
static void /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__setInterrupt(void )
#line 90
{
  bool fired = FALSE;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {



      uint8_t interrupt_in = 1 + /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Compare__get() - /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Timer__get();
      uint8_t newOcr0;
      uint8_t tifr = (uint8_t )/*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__TimerCtrl__getInterruptFlag().flat;

#line 101
      ;
      if ((interrupt_in != 0 && interrupt_in < /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__MINDT) || tifr & (1 << 1)) {
          if (interrupt_in < /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__MINDT) {
              ;
            }
          else {
              ;
            }
          {
#line 109
            __nesc_atomic_end(__nesc_atomic); 
#line 109
            return;
          }
        }

      if (!/*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__set) {
          newOcr0 = /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__MAXT;
          ;
        }
      else 
        {
          uint32_t now = /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Counter__get();

#line 120
          ;

          if ((uint32_t )(now - /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__t0) >= /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__dt) 
            {
              /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__set = FALSE;
              fired = TRUE;
              newOcr0 = /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__MAXT;
            }
          else 
            {


              uint32_t alarm_in = /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__t0 + /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__dt - /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__base;

              if (alarm_in > /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__MAXT) {
                newOcr0 = /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__MAXT;
                }
              else {
#line 136
                if ((uint8_t )alarm_in < /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__MINDT) {
                  newOcr0 = /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__MINDT;
                  }
                else {
#line 139
                  newOcr0 = alarm_in;
                  }
                }
            }
        }
#line 142
      newOcr0--;
      /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__setOcr0(newOcr0);
    }
#line 144
    __nesc_atomic_end(__nesc_atomic); }
  if (fired) {
    /*AlarmCounterMilliP.Atm128AlarmAsyncC.Atm128AlarmAsyncP*/Atm128AlarmAsyncP__0__Alarm__fired();
    }
}

# 42 "/home/wtiberti/WSN/tinyos/tos/platforms/micaz/LocalIeeeEui64C.nc"
static ieee_eui64_t LocalIeeeEui64C__LocalIeeeEui64__getId(void )
#line 42
{
  ieee_eui64_t id;

  id.data[0] = 0x00;
  id.data[1] = 0x12;
  id.data[2] = 0x6d;




  id.data[3] = 'L';
  id.data[4] = 'O';

  id.data[5] = 0;
  id.data[6] = TOS_NODE_ID >> 8;
  id.data[7] = TOS_NODE_ID & 0xff;
  return id;
}

# 147 "../TAKSM.nc"
static void TAKSM__TAKS__ComponentFromHexString(uint8_t *data, const char *s)
{
  int i;
  uint8_t subs[2];

#line 151
  for (i = 0; i < 16 * 2; ++i) {
      uint8_t value;

#line 153
      subs[0] = s[2 * i];
      subs[1] = s[2 * i + 1];
      value = (uint8_t )strtoul((char *)subs, (void *)0, 16);
      data[i] = value;
    }
}

# 187 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer0AsyncP.nc"
__attribute((signal))   void __vector_15(void )
#line 187
{
  HplAtm128Timer0AsyncP__stabiliseTimer0();
  HplAtm128Timer0AsyncP__Compare__fired();
}


__attribute((signal))   void __vector_16(void )
#line 193
{
  HplAtm128Timer0AsyncP__stabiliseTimer0();
  HplAtm128Timer0AsyncP__Timer__overflow();
}

# 204 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer1P.nc"
__attribute((interrupt))   void __vector_12(void )
#line 204
{
  HplAtm128Timer1P__CompareA__fired();
}

__attribute((interrupt))   void __vector_13(void )
#line 208
{
  HplAtm128Timer1P__CompareB__fired();
}

__attribute((interrupt))   void __vector_24(void )
#line 212
{
  HplAtm128Timer1P__CompareC__fired();
}

__attribute((interrupt))   void __vector_11(void )
#line 216
{
  HplAtm128Timer1P__Capture__captured(HplAtm128Timer1P__Capture__get());
}

__attribute((interrupt))   void __vector_14(void )
#line 220
{
  HplAtm128Timer1P__Timer__overflow();
}

# 55 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/pins/HplAtm128InterruptSigP.nc"
__attribute((signal))   void __vector_1(void )
#line 55
{
  HplAtm128InterruptSigP__IntSig0__fired();
}


__attribute((signal))   void __vector_2(void )
#line 60
{
  HplAtm128InterruptSigP__IntSig1__fired();
}


__attribute((signal))   void __vector_3(void )
#line 65
{
  HplAtm128InterruptSigP__IntSig2__fired();
}


__attribute((signal))   void __vector_4(void )
#line 70
{
  HplAtm128InterruptSigP__IntSig3__fired();
}


__attribute((signal))   void __vector_5(void )
#line 75
{
  HplAtm128InterruptSigP__IntSig4__fired();
}


__attribute((signal))   void __vector_6(void )
#line 80
{
  HplAtm128InterruptSigP__IntSig5__fired();
}


__attribute((signal))   void __vector_7(void )
#line 85
{
  HplAtm128InterruptSigP__IntSig6__fired();
}


__attribute((signal))   void __vector_8(void )
#line 90
{
  HplAtm128InterruptSigP__IntSig7__fired();
}

# 119 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/spi/HplAtm128SpiP.nc"
__attribute((signal))   void __vector_17(void )
#line 119
{
  HplAtm128SpiP__SPI__dataReady(HplAtm128SpiP__SPI__read());
}

# 198 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/timer/HplAtm128Timer3P.nc"
__attribute((interrupt))   void __vector_26(void )
#line 198
{
  HplAtm128Timer3P__CompareA__fired();
}

__attribute((interrupt))   void __vector_27(void )
#line 202
{
  HplAtm128Timer3P__CompareB__fired();
}

__attribute((interrupt))   void __vector_28(void )
#line 206
{
  HplAtm128Timer3P__CompareC__fired();
}

__attribute((interrupt))   void __vector_25(void )
#line 210
{
  HplAtm128Timer3P__Capture__captured(HplAtm128Timer3P__Capture__get());
}

__attribute((interrupt))   void __vector_29(void )
#line 214
{
  HplAtm128Timer3P__Timer__overflow();
}

# 64 "/home/wtiberti/WSN/tinyos/tos/lib/printf/SerialPrintfP.nc"
  int printfflush(void )
#line 64
{
  return SUCCESS;
}

# 180 "/home/wtiberti/WSN/tinyos/tos/chips/atm128/HplAtm128UartP.nc"
__attribute((signal))   void __vector_18(void )
#line 180
{
  if ((* (volatile uint8_t *)(0x0B + 0x20) & (1 << 7)) != 0) {
      HplAtm128UartP__HplUart0__rxDone(* (volatile uint8_t *)(0x0C + 0x20));
    }
}

__attribute((interrupt))   void __vector_20(void )
#line 186
{
  HplAtm128UartP__HplUart0__txDone();
}

#line 173
static void HplAtm128UartP__HplUart0__tx(uint8_t data)
#line 173
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 174
    {
      * (volatile uint8_t *)(0x0C + 0x20) = data;
      * (volatile uint8_t *)(0x0B + 0x20) |= 1 << 6;
    }
#line 177
    __nesc_atomic_end(__nesc_atomic); }
}

#line 274
__attribute((signal))   void __vector_30(void )
#line 274
{
  if ((* (volatile uint8_t *)0x9B & (1 << 7)) != 0) {
    HplAtm128UartP__HplUart1__rxDone(* (volatile uint8_t *)0x9C);
    }
}

#line 279
__attribute((interrupt))   void __vector_32(void )
#line 279
{
  HplAtm128UartP__HplUart1__txDone();
}

# 110 "/home/wtiberti/WSN/tinyos/tos/lib/printf/PutcharP.nc"
__attribute((noinline))   int uart_putchar(char c, FILE *stream)
#line 110
{








  return PutcharP__Putchar__putchar(c);
}

