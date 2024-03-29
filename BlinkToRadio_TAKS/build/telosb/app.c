#define nx_struct struct
#define nx_union union
#define dbg(mode, format, ...) ((void)0)
#define dbg_clear(mode, format, ...) ((void)0)
#define dbg_active(mode) 0
# 149 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/include/stddef.h" 3
typedef int ptrdiff_t;
#line 216
typedef unsigned int size_t;
#line 328
typedef long int wchar_t;
#line 437
#line 426
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
# 27 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/machine/_default_types.h" 3
typedef signed char __int8_t;

typedef unsigned char __uint8_t;
#line 41
typedef short int __int16_t;

typedef short unsigned int __uint16_t;
#line 63
typedef long int __int32_t;

typedef long unsigned int __uint32_t;
#line 89
typedef long long int __int64_t;

typedef long long unsigned int __uint64_t;
#line 120
typedef signed char __int_least8_t;

typedef unsigned char __uint_least8_t;
#line 146
typedef short int __int_least16_t;

typedef short unsigned int __uint_least16_t;
#line 168
typedef long int __int_least32_t;

typedef long unsigned int __uint_least32_t;
#line 186
typedef long long int __int_least64_t;

typedef long long unsigned int __uint_least64_t;
#line 200
typedef int __intptr_t;

typedef unsigned int __uintptr_t;
# 19 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/sys/_stdint.h" 3
typedef __int8_t int8_t;
typedef __uint8_t uint8_t;




typedef __int16_t int16_t;
typedef __uint16_t uint16_t;




typedef __int32_t int32_t;
typedef __uint32_t uint32_t;




typedef __int64_t int64_t;
typedef __uint64_t uint64_t;



typedef __intptr_t intptr_t;
typedef __uintptr_t uintptr_t;
# 21 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/stdint.h" 3
typedef __int_least8_t int_least8_t;
typedef __uint_least8_t uint_least8_t;




typedef __int_least16_t int_least16_t;
typedef __uint_least16_t uint_least16_t;




typedef __int_least32_t int_least32_t;
typedef __uint_least32_t uint_least32_t;




typedef __int_least64_t int_least64_t;
typedef __uint_least64_t uint_least64_t;










typedef int int_fast8_t;
typedef unsigned int uint_fast8_t;








typedef int int_fast16_t;
typedef unsigned int uint_fast16_t;








typedef long int int_fast32_t;
typedef long unsigned int uint_fast32_t;








typedef long long int int_fast64_t;
typedef long long unsigned int uint_fast64_t;
#line 130
typedef long long int intmax_t;








typedef long long unsigned int uintmax_t;
# 310 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/inttypes.h" 3
#line 307
typedef struct __nesc_unnamed4244 {
  intmax_t quot;
  intmax_t rem;
} imaxdiv_t;
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
# 6 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/sys/lock.h" 3
typedef int _LOCK_T;
typedef int _LOCK_RECURSIVE_T;
# 16 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/sys/_types.h" 3
typedef long _off_t;



typedef short __dev_t;



typedef unsigned short __uid_t;


typedef unsigned short __gid_t;



__extension__ 
#line 31
typedef long long _off64_t;







typedef long _fpos_t;
#line 55
typedef signed int _ssize_t;
# 357 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/include/stddef.h" 3
typedef unsigned int wint_t;
# 79 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/sys/_types.h" 3
#line 71
typedef struct __nesc_unnamed4245 {

  int __count;
  union __nesc_unnamed4246 {

    wint_t __wch;
    unsigned char __wchb[4];
  } __value;
} _mbstate_t;



typedef _LOCK_RECURSIVE_T _flock_t;




typedef void *_iconv_t;
# 22 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/sys/reent.h" 3
typedef unsigned long __ULong;
#line 38
struct _reent;






struct _Bigint {

  struct _Bigint *_next;
  int _k, _maxwds, _sign, _wds;
  __ULong _x[1];
};


struct __tm {

  int __tm_sec;
  int __tm_min;
  int __tm_hour;
  int __tm_mday;
  int __tm_mon;
  int __tm_year;
  int __tm_wday;
  int __tm_yday;
  int __tm_isdst;
};







struct _on_exit_args {
  void *_fnargs[32];
  void *_dso_handle[32];

  __ULong _fntypes;


  __ULong _is_cxa;
};


struct _atexit {
  struct _atexit *_next;
  int _ind;
  void (*_fns[32])(void );
  struct _on_exit_args *_on_exit_args_ptr;
};
#line 115
struct __sbuf {
  unsigned char *_base;
  int _size;
};
#line 151
struct __sFILE_fake {
  unsigned char *_p;
  int _r;
  int _w;
  short _flags;
  short _file;
  struct __sbuf _bf;
  int _lbfsize;

  struct _reent *_data;
};
#line 179
struct __sFILE {
  unsigned char *_p;
  int _r;
  int _w;
  short _flags;
  short _file;
  struct __sbuf _bf;
  int _lbfsize;


  struct _reent *_data;



  void *_cookie;

  int (*_read)(struct _reent *arg_0x7f25590538f0, void *arg_0x7f2559053bb0, char *arg_0x7f2559053e70, int arg_0x7f2559052120);

  int (*_write)(struct _reent *arg_0x7f2559052890, void *arg_0x7f2559052b50, const char *arg_0x7f2559052e50, int arg_0x7f2559051110);


  _fpos_t (*_seek)(struct _reent *arg_0x7f25590518d0, void *arg_0x7f2559051b90, _fpos_t arg_0x7f2559051e60, int arg_0x7f255904f110);
  int (*_close)(struct _reent *arg_0x7f255904f880, void *arg_0x7f255904fb40);


  struct __sbuf _ub;
  unsigned char *_up;
  int _ur;


  unsigned char _ubuf[3];
  unsigned char _nbuf[1];


  struct __sbuf _lb;


  int _blksize;
  _off_t _offset;






  _flock_t _lock;

  _mbstate_t _mbstate;
  int _flags2;
};
#line 285
typedef struct __sFILE __FILE;



struct _glue {

  struct _glue *_next;
  int _niobs;
  __FILE *_iobs;
};
#line 317
struct _rand48 {
  unsigned short _seed[3];
  unsigned short _mult[3];
  unsigned short _add;


  __extension__ unsigned long long _rand_next;
};
#line 342
struct _mprec {


  struct _Bigint *_result;
  int _result_k;
  struct _Bigint *_p5s;
  struct _Bigint **_freelist;
};


struct _misc_reent {


  char *_strtok_last;
  _mbstate_t _mblen_state;
  _mbstate_t _wctomb_state;
  _mbstate_t _mbtowc_state;
  char _l64a_buf[8];
  int _getdate_err;
  _mbstate_t _mbrlen_state;
  _mbstate_t _mbrtowc_state;
  _mbstate_t _mbsrtowcs_state;
  _mbstate_t _wcrtomb_state;
  _mbstate_t _wcsrtombs_state;
};



struct _reent {



  int _errno;




  __FILE *_stdin, *_stdout, *_stderr;

  int _inc;

  char *_emergency;

  int __sdidinit;

  int _current_category;
  const char *_current_locale;

  struct _mprec *_mp;

  void (*__cleanup)(struct _reent *arg_0x7f255903f700);

  int _gamma_signgam;


  int _cvtlen;
  char *_cvtbuf;

  struct _rand48 *_r48;
  struct __tm *_localtime_buf;
  char *_asctime_buf;


  void (**_sig_func)(int arg_0x7f255903ea90);



  struct _atexit *_atexit;
  struct _atexit _atexit0;


  struct _glue __sglue;
  __FILE *__sf;
  struct _misc_reent *_misc;
  char *_signal_buf;
};

struct __sFILE_fake;
struct __sFILE_fake;
struct __sFILE_fake;
#line 765
struct _reent;
struct _reent;
# 22 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/string.h" 3
int memcmp(const void *arg_0x7f255902cc10, const void *arg_0x7f255902b020, size_t arg_0x7f255902b2e0);
void *memcpy(void *arg_0x7f255902bb50, const void *arg_0x7f255902be50, size_t arg_0x7f2559029150);

void *memset(void *arg_0x7f25590288d0, int arg_0x7f2559028b50, size_t arg_0x7f2559028e10);
# 35 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/stdlib.h" 3
#line 31
typedef struct __nesc_unnamed4247 {

  int quot;
  int rem;
} div_t;





#line 37
typedef struct __nesc_unnamed4248 {

  long quot;
  long rem;
} ldiv_t;






#line 44
typedef struct __nesc_unnamed4249 {

  long long int quot;
  long long int rem;
} lldiv_t;




typedef int (*__compar_fn_t)(const void *arg_0x7f2558fed7c0, const void *arg_0x7f2558fedac0);
#line 136
int rand(void );










void srand(unsigned __seed);
#line 161
unsigned long strtoul(const char *__n, char **__end_PTR, int __base);
# 15 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/math.h" 3
union __dmath {

  double d;
  __ULong i[2];
};

union __fmath {

  float f;
  __ULong i[1];
};


union __ldmath {

  long double ld;
  __ULong i[4];
};
#line 154
typedef float float_t;
typedef double double_t;
#line 588
struct exception {


  int type;
  char *name;
  double arg1;
  double arg2;
  double retval;
  int err;
};
#line 652
enum __fdlibm_version {

  __fdlibm_ieee = -1, 
  __fdlibm_svid, 
  __fdlibm_xopen, 
  __fdlibm_posix
};




enum __fdlibm_version;
# 25 "/home/wtiberti/WSN/tinyos/tos/system/tos.h"
typedef uint8_t bool;
enum __nesc_unnamed4250 {
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
# 48 "/opt/ti/msp430-gcc-7.3.2.154_linux64/include/in430.h"
typedef unsigned int __istate_t;
# 167 "/opt/ti/msp430-gcc-7.3.2.154_linux64/include/msp430f1611.h"
extern volatile uint8_t ME1;
#line 183
extern volatile uint8_t ME2;










extern volatile uint16_t WDTCTL;
#line 259
extern volatile uint8_t P1OUT;
extern volatile uint8_t P1DIR;
extern volatile uint8_t P1IFG;
extern volatile uint8_t P1IES;
extern volatile uint8_t P1IE;
extern volatile uint8_t P1SEL;


extern volatile uint8_t P2OUT;
extern volatile uint8_t P2DIR;
extern volatile uint8_t P2IFG;

extern volatile uint8_t P2IE;
extern volatile uint8_t P2SEL;
#line 284
extern volatile uint8_t P3OUT;
extern volatile uint8_t P3DIR;
extern volatile uint8_t P3SEL;


extern volatile uint8_t P4OUT;
extern volatile uint8_t P4DIR;
extern volatile uint8_t P4SEL;
#line 303
extern volatile uint8_t P5OUT;
extern volatile uint8_t P5DIR;
extern volatile uint8_t P5SEL;


extern volatile uint8_t P6OUT;
extern volatile uint8_t P6DIR;
extern volatile uint8_t P6SEL;
#line 351
extern volatile uint8_t U0CTL;
extern volatile uint8_t U0TCTL;

extern volatile uint8_t U0MCTL;
extern volatile uint8_t U0BR0;
extern volatile uint8_t U0BR1;
extern volatile uint8_t U0RXBUF;
#line 400
extern volatile uint8_t U1CTL;
extern volatile uint8_t U1TCTL;

extern volatile uint8_t U1MCTL;
extern volatile uint8_t U1BR0;
extern volatile uint8_t U1BR1;
extern volatile uint8_t U1RXBUF;
#line 534
extern volatile uint16_t TACTL;
extern volatile uint16_t TACCTL0;
extern volatile uint16_t TACCTL1;
extern volatile uint16_t TACCTL2;
extern volatile uint16_t TAR;
#line 657
extern volatile uint16_t TBCCTL0;






extern volatile uint16_t TBR;
extern volatile uint16_t TBCCR0;
#line 783
extern volatile uint8_t DCOCTL;
extern volatile uint8_t BCSCTL1;
extern volatile uint8_t BCSCTL2;
#line 945
extern volatile uint16_t ADC12CTL0;
extern volatile uint16_t ADC12CTL1;
# 580 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/msp430hardware.h"
typedef uint8_t mcu_power_t  ;
static inline mcu_power_t mcombine(mcu_power_t m1, mcu_power_t m2)  ;



enum __nesc_unnamed4251 {
  MSP430_POWER_ACTIVE = 0, 
  MSP430_POWER_LPM0 = 1, 
  MSP430_POWER_LPM1 = 2, 
  MSP430_POWER_LPM2 = 3, 
  MSP430_POWER_LPM3 = 4, 
  MSP430_POWER_LPM4 = 5
};





static __inline void __nesc_disable_interrupt(void ) __attribute((always_inline))  ;









static __inline void __nesc_enable_interrupt(void ) __attribute((always_inline))  ;
#line 623
typedef uint16_t __nesc_atomic_t;
__inline __nesc_atomic_t __nesc_atomic_start(void ) __attribute((always_inline)) ;
__inline void __nesc_atomic_end(__nesc_atomic_t reenable_interrupts) __attribute((always_inline)) ;
#line 655
__inline __nesc_atomic_t __nesc_atomic_start(void )  __attribute((always_inline))  ;
#line 672
__inline void __nesc_atomic_end(__nesc_atomic_t reenable_interrupts)  __attribute((always_inline))  ;
#line 688
typedef struct { unsigned char nxdata[4]; } __attribute__((packed)) nx_float;typedef float __nesc_nxbase_nx_float  ;
#line 705
enum __nesc_unnamed4252 {
  MSP430_PORT_RESISTOR_INVALID, 
  MSP430_PORT_RESISTOR_OFF, 
  MSP430_PORT_RESISTOR_PULLDOWN, 
  MSP430_PORT_RESISTOR_PULLUP
};


enum __nesc_unnamed4253 {
  MSP430_PORT_DRIVE_STRENGTH_INVALID, 
  MSP430_PORT_DRIVE_STRENGTH_REDUCED, 
  MSP430_PORT_DRIVE_STRENGTH_FULL
};
# 8 "/home/wtiberti/WSN/tinyos/tos/platforms/telosb/hardware.h"
enum __nesc_unnamed4254 {
  TOS_SLEEP_NONE = MSP430_POWER_ACTIVE
};
#line 36
static inline void TOSH_SET_SIMO0_PIN()  ;
#line 36
static inline void TOSH_CLR_SIMO0_PIN()  ;
#line 36
static inline void TOSH_MAKE_SIMO0_OUTPUT()  ;
static inline void TOSH_SET_UCLK0_PIN()  ;
#line 37
static inline void TOSH_CLR_UCLK0_PIN()  ;
#line 37
static inline void TOSH_MAKE_UCLK0_OUTPUT()  ;
#line 79
enum __nesc_unnamed4255 {

  TOSH_HUMIDITY_ADDR = 5, 
  TOSH_HUMIDTEMP_ADDR = 3, 
  TOSH_HUMIDITY_RESET = 0x1E
};



static inline void TOSH_SET_FLASH_CS_PIN()  ;
#line 88
static inline void TOSH_CLR_FLASH_CS_PIN()  ;
#line 88
static inline void TOSH_MAKE_FLASH_CS_OUTPUT()  ;
static inline void TOSH_SET_FLASH_HOLD_PIN()  ;
#line 89
static inline void TOSH_MAKE_FLASH_HOLD_OUTPUT()  ;
# 41 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.h"
typedef struct __nesc_unnamed4256 {
#line 41
  int notUsed;
} 
#line 41
TSecond;
typedef struct __nesc_unnamed4257 {
#line 42
  int notUsed;
} 
#line 42
TMilli;
typedef struct __nesc_unnamed4258 {
#line 43
  int notUsed;
} 
#line 43
T32khz;
typedef struct __nesc_unnamed4259 {
#line 44
  int notUsed;
} 
#line 44
TMicro;
# 12 "BlinkToRadio.h"
enum __nesc_unnamed4260 {
  AM_BLINKTORADIO = 6, 
  TIMER_PERIOD_MILLI = 1000
};





#line 17
typedef struct BlinkToRadioMsg {
  uint8_t payload[16];
  uint8_t mac[4];
  uint8_t kri[32];
} BlinkToRadioMsg;
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.h"
enum __nesc_unnamed4261 {
  MSP430TIMER_CM_NONE = 0, 
  MSP430TIMER_CM_RISING = 1, 
  MSP430TIMER_CM_FALLING = 2, 
  MSP430TIMER_CM_BOTH = 3, 

  MSP430TIMER_CCI_A = 0, 
  MSP430TIMER_CCI_B = 1, 
  MSP430TIMER_CCI_GND = 2, 
  MSP430TIMER_CCI_VCC = 3, 

  MSP430TIMER_STOP_MODE = 0, 
  MSP430TIMER_UP_MODE = 1, 
  MSP430TIMER_CONTINUOUS_MODE = 2, 
  MSP430TIMER_UPDOWN_MODE = 3, 

  MSP430TIMER_TACLK = 0, 
  MSP430TIMER_TBCLK = 0, 
  MSP430TIMER_ACLK = 1, 
  MSP430TIMER_SMCLK = 2, 
  MSP430TIMER_INCLK = 3, 

  MSP430TIMER_CLOCKDIV_1 = 0, 
  MSP430TIMER_CLOCKDIV_2 = 1, 
  MSP430TIMER_CLOCKDIV_4 = 2, 
  MSP430TIMER_CLOCKDIV_8 = 3
};
#line 82
#line 70
typedef struct __nesc_unnamed4262 {
  int ccifg : 1;
  int cov : 1;
  int out : 1;
  int cci : 1;
  int ccie : 1;
  int outmod : 3;
  int cap : 1;
  int clld : 2;
  int scs : 1;
  int ccis : 2;
  int cm : 2;
} msp430_compare_control_t;










#line 84
typedef struct __nesc_unnamed4263 {
  int taifg : 1;
  int taie : 1;
  int taclr : 1;
  int _unused0 : 1;
  int mc : 2;
  int id : 2;
  int tassel : 2;
  int _unused1 : 6;
} msp430_timer_a_control_t;
#line 107
#line 95
typedef struct __nesc_unnamed4264 {
  int tbifg : 1;
  int tbie : 1;
  int tbclr : 1;
  int _unused0 : 1;
  int mc : 2;
  int id : 2;
  int tbssel : 2;
  int _unused1 : 1;
  int cntl : 2;
  int tbclgrp : 2;
  int _unused2 : 1;
} msp430_timer_b_control_t;
# 43 "/home/wtiberti/WSN/tinyos/tos/types/Leds.h"
enum __nesc_unnamed4265 {
  LEDS_LED0 = 1 << 0, 
  LEDS_LED1 = 1 << 1, 
  LEDS_LED2 = 1 << 2, 
  LEDS_LED3 = 1 << 3, 
  LEDS_LED4 = 1 << 4, 
  LEDS_LED5 = 1 << 5, 
  LEDS_LED6 = 1 << 6, 
  LEDS_LED7 = 1 << 7
};
# 40 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/include/stdarg.h" 3
typedef __builtin_va_list __gnuc_va_list;
# 28 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/sys/types.h" 3
typedef __uint8_t u_int8_t;


typedef __uint16_t u_int16_t;


typedef __uint32_t u_int32_t;


typedef __uint64_t u_int64_t;
# 19 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/machine/types.h" 3
typedef long int __off_t;
typedef int __pid_t;

__extension__ 
#line 22
typedef long long int __loff_t;





typedef long __suseconds_t;
# 41 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/sys/_sigset.h" 3
typedef unsigned long __sigset_t;
# 35 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/sys/_timeval.h" 3
typedef __suseconds_t suseconds_t;




typedef long time_t;










struct timeval {
  time_t tv_sec;
  suseconds_t tv_usec;
};
# 44 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/sys/_timespec.h" 3
struct timespec {
  time_t tv_sec;
  long tv_nsec;
};
# 58 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/sys/timespec.h" 3
struct itimerspec {
  struct timespec it_interval;
  struct timespec it_value;
};
# 31 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/sys/select.h" 3
typedef __sigset_t sigset_t;
#line 45
typedef unsigned long fd_mask;









#line 53
typedef struct _types_fd_set {
  fd_mask fds_bits[(64 + (sizeof(fd_mask ) * 8 - 1)) / (sizeof(fd_mask ) * 8)];
} _types_fd_set;
# 94 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/sys/types.h" 3
typedef unsigned char u_char;



typedef unsigned short u_short;



typedef unsigned int u_int;



typedef unsigned long u_long;







typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;



typedef unsigned long clock_t;









typedef long daddr_t;



typedef char *caddr_t;








typedef unsigned short ino_t;
#line 172
typedef _off_t off_t;
typedef __dev_t dev_t;
typedef __uid_t uid_t;
typedef __gid_t gid_t;





typedef int pid_t;







typedef long key_t;



typedef _ssize_t ssize_t;
#line 209
typedef unsigned int mode_t __attribute((__mode__(__SI__))) ;




typedef unsigned short nlink_t;






typedef unsigned long clockid_t;




typedef unsigned long timer_t;



typedef unsigned long useconds_t;






typedef __int64_t sbintime_t;
# 53 "/opt/ti/msp430-gcc-7.3.2.154_linux64/bin/../lib/gcc/msp430-elf/7.3.2/../../../../msp430-elf/include/stdio.h" 3
typedef __FILE FILE;






typedef _fpos_t fpos_t;
#line 181
int printf(const char *arg_0x7f255868d0d0, ...) __attribute((__format__(__printf__, 1, 2))) ;
#line 201
int putchar(int arg_0x7f255867e110);
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
enum __nesc_unnamed4266 {

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


enum __nesc_unnamed4267 {

  CC2420_INVALID_TIMESTAMP = 0x80000000L
};
# 6 "/home/wtiberti/WSN/tinyos/tos/types/AM.h"
typedef nx_uint8_t nx_am_id_t;
typedef nx_uint8_t nx_am_group_t;
typedef nx_uint16_t nx_am_addr_t;

typedef uint8_t am_id_t;
typedef uint8_t am_group_t;
typedef uint16_t am_addr_t;

enum __nesc_unnamed4268 {
  AM_BROADCAST_ADDR = 0xffff
};









enum __nesc_unnamed4269 {
  TOS_AM_GROUP = 0x22, 
  TOS_AM_ADDRESS = 1
};
# 83 "/home/wtiberti/WSN/tinyos/tos/lib/serial/Serial.h"
typedef uint8_t uart_id_t;



enum __nesc_unnamed4270 {
  HDLC_FLAG_BYTE = 0x7e, 
  HDLC_CTLESC_BYTE = 0x7d
};



enum __nesc_unnamed4271 {
  AM_SERIAL_PACKET = 0, 
  TOS_SERIAL_ACTIVE_MESSAGE_ID = 0, 
  TOS_SERIAL_CC1000_ID = 1, 
  TOS_SERIAL_802_15_4_ID = 2, 
  TOS_SERIAL_UNKNOWN_ID = 255
};


enum __nesc_unnamed4272 {
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
# 59 "/home/wtiberti/WSN/tinyos/tos/platforms/telosa/platform_message.h"
#line 56
typedef union message_header {
  cc2420_header_t cc2420;
  serial_header_t serial;
} message_header_t;



#line 61
typedef union TOSRadioFooter {
  cc2420_footer_t cc2420;
} message_footer_t;






#line 65
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
enum __nesc_unnamed4273 {
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
typedef struct __nesc_unnamed4274 {
  uint8_t ieee_mode : 2;
  union __nesc_unnamed4275 {
    ieee154_saddr_t saddr;
    ieee154_laddr_t laddr;
  } ieee_addr;
} ieee154_addr_t;
#line 100
enum __nesc_unnamed4276 {
  IEEE154_BROADCAST_ADDR = 0xffff, 
  IEEE154_BROADCAST_PAN = 0xffff, 
  IEEE154_LINK_MTU = 127
};

struct ieee154_frame_addr {
  ieee154_addr_t ieee_src;
  ieee154_addr_t ieee_dst;
  ieee154_panid_t ieee_dstpan;
};

enum __nesc_unnamed4277 {
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
enum __nesc_unnamed4278 {
  TOS_IEEE154_SHORT_ADDRESS = 1, 
  TOS_IEEE154_PAN_ID = 22
};
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/msp430usart.h"
#line 51
typedef enum __nesc_unnamed4279 {
  USART_NONE = 0, 
  USART_UART = 1, 
  USART_UART_TX = 2, 
  USART_UART_RX = 3, 
  USART_SPI = 4, 
  USART_I2C = 5
} msp430_usartmode_t;










#line 60
typedef struct __nesc_unnamed4280 {
  unsigned int swrst : 1;
  unsigned int mm : 1;
  unsigned int sync : 1;
  unsigned int listen : 1;
  unsigned int clen : 1;
  unsigned int spb : 1;
  unsigned int pev : 1;
  unsigned int pena : 1;
} __attribute((packed))  msp430_uctl_t;









#line 71
typedef struct __nesc_unnamed4281 {
  unsigned int txept : 1;
  unsigned int stc : 1;
  unsigned int txwake : 1;
  unsigned int urxse : 1;
  unsigned int ssel : 2;
  unsigned int ckpl : 1;
  unsigned int ckph : 1;
} __attribute((packed))  msp430_utctl_t;










#line 81
typedef struct __nesc_unnamed4282 {
  unsigned int rxerr : 1;
  unsigned int rxwake : 1;
  unsigned int urxwie : 1;
  unsigned int urxeie : 1;
  unsigned int brk : 1;
  unsigned int oe : 1;
  unsigned int pe : 1;
  unsigned int fe : 1;
} __attribute((packed))  msp430_urctl_t;
#line 119
#line 101
typedef struct __nesc_unnamed4283 {
  unsigned int ubr : 16;


  unsigned int  : 1;
  unsigned int mm : 1;
  unsigned int  : 1;
  unsigned int listen : 1;
  unsigned int clen : 1;
  unsigned int  : 3;


  unsigned int  : 1;
  unsigned int stc : 1;
  unsigned int  : 2;
  unsigned int ssel : 2;
  unsigned int ckpl : 1;
  unsigned int ckph : 1;
} __attribute((packed))  msp430_spi_config_t;





#line 121
typedef struct __nesc_unnamed4284 {
  uint16_t ubr;
  uint8_t uctl;
  uint8_t utctl;
} msp430_spi_registers_t;




#line 127
typedef union __nesc_unnamed4285 {
  msp430_spi_config_t spiConfig;
  msp430_spi_registers_t spiRegisters;
} msp430_spi_union_config_t;





const msp430_spi_union_config_t msp430_spi_default_config = { { 
.ubr = 2, 
.ssel = 2, 
.clen = 1, 
.listen = 0, 
.mm = 1, 
.ckph = 1, 
.ckpl = 0, 
.stc = 1 } };
#line 181
#line 156
typedef enum __nesc_unnamed4286 {

  UBR_32KIHZ_1200 = 0x001B, UMCTL_32KIHZ_1200 = 0x94, 
  UBR_32KIHZ_1800 = 0x0012, UMCTL_32KIHZ_1800 = 0x84, 
  UBR_32KIHZ_2400 = 0x000D, UMCTL_32KIHZ_2400 = 0x6D, 
  UBR_32KIHZ_4800 = 0x0006, UMCTL_32KIHZ_4800 = 0x77, 
  UBR_32KIHZ_9600 = 0x0003, UMCTL_32KIHZ_9600 = 0x29, 

  UBR_1MIHZ_1200 = 0x0369, UMCTL_1MIHZ_1200 = 0x7B, 
  UBR_1MIHZ_1800 = 0x0246, UMCTL_1MIHZ_1800 = 0x55, 
  UBR_1MIHZ_2400 = 0x01B4, UMCTL_1MIHZ_2400 = 0xDF, 
  UBR_1MIHZ_4800 = 0x00DA, UMCTL_1MIHZ_4800 = 0xAA, 
  UBR_1MIHZ_9600 = 0x006D, UMCTL_1MIHZ_9600 = 0x44, 
  UBR_1MIHZ_19200 = 0x0036, UMCTL_1MIHZ_19200 = 0xB5, 
  UBR_1MIHZ_38400 = 0x001B, UMCTL_1MIHZ_38400 = 0x94, 
  UBR_1MIHZ_57600 = 0x0012, UMCTL_1MIHZ_57600 = 0x84, 
  UBR_1MIHZ_76800 = 0x000D, UMCTL_1MIHZ_76800 = 0x6D, 
  UBR_1MIHZ_115200 = 0x0009, UMCTL_1MIHZ_115200 = 0x10, 
  UBR_1MIHZ_230400 = 0x0004, UMCTL_1MIHZ_230400 = 0x55, 


  UBR_4MIHZ_4800 = 0x0369, UMCTL_4MIHZ_4800 = 0xfb, 
  UBR_4MIHZ_9600 = 0x01b4, UMCTL_4MIHZ_9600 = 0xdf, 
  UBR_4MIHZ_57600 = 0x0048, UMCTL_4MIHZ_57600 = 0xfb, 
  UBR_4MIHZ_115200 = 0x0024, UMCTL_4MIHZ_115200 = 0x4a
} msp430_uart_rate_t;
#line 213
#line 183
typedef struct __nesc_unnamed4287 {
  unsigned int ubr : 16;
  unsigned int umctl : 8;


  unsigned int  : 1;
  unsigned int mm : 1;
  unsigned int  : 1;
  unsigned int listen : 1;
  unsigned int clen : 1;
  unsigned int spb : 1;
  unsigned int pev : 1;
  unsigned int pena : 1;


  unsigned int  : 3;
  unsigned int urxse : 1;
  unsigned int ssel : 2;
  unsigned int ckpl : 1;
  unsigned int  : 1;


  unsigned int  : 2;
  unsigned int urxwie : 1;
  unsigned int urxeie : 1;
  unsigned int  : 4;


  unsigned int utxe : 1;
  unsigned int urxe : 1;
} __attribute((packed))  msp430_uart_config_t;








#line 215
typedef struct __nesc_unnamed4288 {
  uint16_t ubr;
  uint8_t umctl;
  uint8_t uctl;
  uint8_t utctl;
  uint8_t urctl;
  uint8_t ume;
} msp430_uart_registers_t;




#line 224
typedef union __nesc_unnamed4289 {
  msp430_uart_config_t uartConfig;
  msp430_uart_registers_t uartRegisters;
} msp430_uart_union_config_t;

const msp430_uart_union_config_t msp430_uart_default_config = { { 
.ubr = UBR_4MIHZ_57600, 
.umctl = UMCTL_4MIHZ_57600, 
.ssel = 2, 
.pena = 0, 
.pev = 0, 
.spb = 0, 
.clen = 1, 
.listen = 0, 
.mm = 0, 
.ckpl = 0, 
.urxse = 0, 
.urxeie = 1, 
.urxwie = 0, 
.utxe = 1, 
.urxe = 1 } };










#line 247
typedef struct __nesc_unnamed4290 {
  unsigned int i2cstt : 1;
  unsigned int i2cstp : 1;
  unsigned int i2cstb : 1;
  unsigned int i2cctrx : 1;
  unsigned int i2cssel : 2;
  unsigned int i2ccrm : 1;
  unsigned int i2cword : 1;
} __attribute((packed))  msp430_i2ctctl_t;
#line 284
#line 260
typedef struct __nesc_unnamed4291 {

  unsigned int  : 1;
  unsigned int mst : 1;
  unsigned int  : 1;
  unsigned int listen : 1;
  unsigned int xa : 1;
  unsigned int  : 1;
  unsigned int txdmaen : 1;
  unsigned int rxdmaen : 1;


  unsigned int  : 4;
  unsigned int i2cssel : 2;
  unsigned int i2crm : 1;
  unsigned int i2cword : 1;

  unsigned int i2cpsc : 8;
  unsigned int i2csclh : 8;
  unsigned int i2cscll : 8;


  unsigned int i2coa : 10;
  unsigned int  : 6;
} __attribute((packed))  msp430_i2c_config_t;








#line 286
typedef struct __nesc_unnamed4292 {
  uint8_t uctl;
  uint8_t i2ctctl;
  uint8_t i2cpsc;
  uint8_t i2csclh;
  uint8_t i2cscll;
  uint16_t i2coa;
} msp430_i2c_registers_t;




#line 295
typedef union __nesc_unnamed4293 {
  msp430_i2c_config_t i2cConfig;
  msp430_i2c_registers_t i2cRegisters;
} msp430_i2c_union_config_t;
#line 315
typedef uint8_t uart_speed_t;
typedef uint8_t uart_parity_t;
typedef uint8_t uart_duplex_t;

enum __nesc_unnamed4294 {
  TOS_UART_1200 = 0, 
  TOS_UART_1800 = 1, 
  TOS_UART_2400 = 2, 
  TOS_UART_4800 = 3, 
  TOS_UART_9600 = 4, 
  TOS_UART_19200 = 5, 
  TOS_UART_38400 = 6, 
  TOS_UART_57600 = 7, 
  TOS_UART_76800 = 8, 
  TOS_UART_115200 = 9, 
  TOS_UART_230400 = 10
};

enum __nesc_unnamed4295 {
  TOS_UART_OFF, 
  TOS_UART_RONLY, 
  TOS_UART_TONLY, 
  TOS_UART_DUPLEX
};

enum __nesc_unnamed4296 {
  TOS_UART_PARITY_NONE, 
  TOS_UART_PARITY_EVEN, 
  TOS_UART_PARITY_ODD
};
# 33 "/home/wtiberti/WSN/tinyos/tos/types/Resource.h"
typedef uint8_t resource_client_id_t;
# 29 "/home/wtiberti/WSN/tinyos/tos/platforms/epic/chips/ds2411/PlatformIeeeEui64.h"
enum __nesc_unnamed4297 {
  IEEE_EUI64_COMPANY_ID_0 = 0x00, 
  IEEE_EUI64_COMPANY_ID_1 = 0x12, 
  IEEE_EUI64_COMPANY_ID_2 = 0x6d, 
  IEEE_EUI64_SERIAL_ID_0 = 'E', 
  IEEE_EUI64_SERIAL_ID_1 = 'P'
};
# 6 "/home/wtiberti/WSN/tinyos/tos/chips/ds2411/ds2411.h"
enum __nesc_unnamed4298 {
  DS2411_SERIAL_LENGTH = 6, 
  DS2411_DATA_LENGTH = 8
};








#line 11
typedef union ds241_serial_t {
  uint8_t data[DS2411_DATA_LENGTH];
  struct  {
    uint8_t family_code;
    uint8_t serial[DS2411_SERIAL_LENGTH];
    uint8_t crc;
  } ;
} ds2411_serial_t;
# 43 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420TimeSyncMessage.h"
typedef nx_uint32_t timesync_radio_t;





#line 45
typedef nx_struct timesync_footer_t {

  nx_am_id_t type;
  timesync_radio_t timestamp;
} __attribute__((packed)) timesync_footer_t;
# 40 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430HybridAlarmCounter.h"
#line 38
typedef struct T2ghz {
  uint8_t dummy;
} T2ghz;
typedef TMilli BlinkToRadioC__Timer0__precision_tag;
enum /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Timer*/Msp430Timer32khzC__0____nesc_unnamed4299 {
  Msp430Timer32khzC__0__ALARM_ID = 0U
};
typedef T32khz /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__frequency_tag;
typedef /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__frequency_tag /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__precision_tag;
typedef uint16_t /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__size_type;
typedef T32khz /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__frequency_tag;
typedef /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__frequency_tag /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__precision_tag;
typedef uint16_t /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__size_type;
typedef TMilli /*CounterMilli32C.Transform*/TransformCounterC__0__to_precision_tag;
typedef uint32_t /*CounterMilli32C.Transform*/TransformCounterC__0__to_size_type;
typedef T32khz /*CounterMilli32C.Transform*/TransformCounterC__0__from_precision_tag;
typedef uint16_t /*CounterMilli32C.Transform*/TransformCounterC__0__from_size_type;
typedef uint32_t /*CounterMilli32C.Transform*/TransformCounterC__0__upper_count_type;
typedef /*CounterMilli32C.Transform*/TransformCounterC__0__from_precision_tag /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__precision_tag;
typedef /*CounterMilli32C.Transform*/TransformCounterC__0__from_size_type /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__size_type;
typedef /*CounterMilli32C.Transform*/TransformCounterC__0__to_precision_tag /*CounterMilli32C.Transform*/TransformCounterC__0__Counter__precision_tag;
typedef /*CounterMilli32C.Transform*/TransformCounterC__0__to_size_type /*CounterMilli32C.Transform*/TransformCounterC__0__Counter__size_type;
typedef TMilli /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_precision_tag;
typedef uint32_t /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type;
typedef T32khz /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__from_precision_tag;
typedef uint16_t /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__from_size_type;
typedef /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_precision_tag /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__precision_tag;
typedef /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__size_type;
typedef /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__from_precision_tag /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__precision_tag;
typedef /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__from_size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__size_type;
typedef /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_precision_tag /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Counter__precision_tag;
typedef /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Counter__size_type;
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
enum CC2420ActiveMessageC____nesc_unnamed4300 {
  CC2420ActiveMessageC__CC2420_AM_SEND_ID = 0U
};
typedef T32khz CC2420ControlP__StartupTimer__precision_tag;
typedef uint32_t CC2420ControlP__StartupTimer__size_type;
typedef uint16_t CC2420ControlP__ReadRssi__val_t;
enum /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Timer*/Msp430Timer32khzC__1____nesc_unnamed4301 {
  Msp430Timer32khzC__1__ALARM_ID = 1U
};
typedef T32khz /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__frequency_tag;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__frequency_tag /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__precision_tag;
typedef uint16_t /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__size_type;
typedef T32khz /*Counter32khz32C.Transform*/TransformCounterC__1__to_precision_tag;
typedef uint32_t /*Counter32khz32C.Transform*/TransformCounterC__1__to_size_type;
typedef T32khz /*Counter32khz32C.Transform*/TransformCounterC__1__from_precision_tag;
typedef uint16_t /*Counter32khz32C.Transform*/TransformCounterC__1__from_size_type;
typedef uint16_t /*Counter32khz32C.Transform*/TransformCounterC__1__upper_count_type;
typedef /*Counter32khz32C.Transform*/TransformCounterC__1__from_precision_tag /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__precision_tag;
typedef /*Counter32khz32C.Transform*/TransformCounterC__1__from_size_type /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__size_type;
typedef /*Counter32khz32C.Transform*/TransformCounterC__1__to_precision_tag /*Counter32khz32C.Transform*/TransformCounterC__1__Counter__precision_tag;
typedef /*Counter32khz32C.Transform*/TransformCounterC__1__to_size_type /*Counter32khz32C.Transform*/TransformCounterC__1__Counter__size_type;
typedef T32khz /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_precision_tag;
typedef uint32_t /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type;
typedef T32khz /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__from_precision_tag;
typedef uint16_t /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__from_size_type;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_precision_tag /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__precision_tag;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__size_type;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__from_precision_tag /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__precision_tag;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__from_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__size_type;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_precision_tag /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Counter__precision_tag;
typedef /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Counter__size_type;
enum /*CC2420ControlC.Spi*/CC2420SpiC__0____nesc_unnamed4302 {
  CC2420SpiC__0__CLIENT_ID = 0U
};
enum /*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0____nesc_unnamed4303 {
  Msp430Spi0C__0__CLIENT_ID = 0U
};
enum /*CC2420SpiWireC.HplCC2420SpiC.SpiC.UsartC*/Msp430Usart0C__0____nesc_unnamed4304 {
  Msp430Usart0C__0__CLIENT_ID = 0U
};
enum /*CC2420ControlC.SyncSpiC*/CC2420SpiC__1____nesc_unnamed4305 {
  CC2420SpiC__1__CLIENT_ID = 1U
};
enum /*CC2420ControlC.RssiResource*/CC2420SpiC__2____nesc_unnamed4306 {
  CC2420SpiC__2__CLIENT_ID = 2U
};
typedef TMicro OneWireMasterP__BusyWait__precision_tag;
typedef uint16_t OneWireMasterP__BusyWait__size_type;
typedef TMicro /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__precision_tag;
typedef uint16_t /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__size_type;
typedef /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__precision_tag /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__BusyWait__precision_tag;
typedef /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__size_type /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__BusyWait__size_type;
typedef /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__precision_tag /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__precision_tag;
typedef /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__size_type /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__size_type;
typedef TMicro /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__frequency_tag;
typedef /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__frequency_tag /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Counter__precision_tag;
typedef uint16_t /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Counter__size_type;
typedef T32khz CC2420TransmitP__PacketTimeStamp__precision_tag;
typedef uint32_t CC2420TransmitP__PacketTimeStamp__size_type;
typedef T32khz CC2420TransmitP__BackoffTimer__precision_tag;
typedef uint32_t CC2420TransmitP__BackoffTimer__size_type;
enum /*CC2420TransmitC.Spi*/CC2420SpiC__3____nesc_unnamed4307 {
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
enum /*CC2420ReceiveC.Spi*/CC2420SpiC__4____nesc_unnamed4308 {
  CC2420SpiC__4__CLIENT_ID = 4U
};
typedef uint16_t RandomMlcgC__SeedInit__parameter;
enum CC2420TinyosNetworkC____nesc_unnamed4309 {
  CC2420TinyosNetworkC__TINYOS_N_NETWORKS = 1U
};
enum AMQueueP____nesc_unnamed4310 {
  AMQueueP__NUM_CLIENTS = 1U
};
typedef TMicro TAKSM__LocalTime__precision_tag;
typedef TMicro Msp430HybridAlarmCounterP__CounterMicro__precision_tag;
typedef uint16_t Msp430HybridAlarmCounterP__CounterMicro__size_type;
typedef T2ghz Msp430HybridAlarmCounterP__Counter2ghz__precision_tag;
typedef uint32_t Msp430HybridAlarmCounterP__Counter2ghz__size_type;
typedef T32khz Msp430HybridAlarmCounterP__Alarm32khz__precision_tag;
typedef uint16_t Msp430HybridAlarmCounterP__Alarm32khz__size_type;
typedef T2ghz Msp430HybridAlarmCounterP__Alarm2ghz__precision_tag;
typedef uint32_t Msp430HybridAlarmCounterP__Alarm2ghz__size_type;
typedef TMicro Msp430HybridAlarmCounterP__AlarmMicro__precision_tag;
typedef uint16_t Msp430HybridAlarmCounterP__AlarmMicro__size_type;
typedef T32khz Msp430HybridAlarmCounterP__Counter32khz__precision_tag;
typedef uint16_t Msp430HybridAlarmCounterP__Counter32khz__size_type;
enum /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Timer*/Msp430Timer32khzC__2____nesc_unnamed4311 {
  Msp430Timer32khzC__2__ALARM_ID = 2U
};
typedef T32khz /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__frequency_tag;
typedef /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__frequency_tag /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Alarm__precision_tag;
typedef uint16_t /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Alarm__size_type;
enum /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Timer*/Msp430TimerMicroC__0____nesc_unnamed4312 {
  Msp430TimerMicroC__0__ALARM_ID = 0U
};
typedef TMicro /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__frequency_tag;
typedef /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__frequency_tag /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__precision_tag;
typedef uint16_t /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__size_type;
typedef TMicro /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__to_precision_tag;
typedef uint32_t /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__to_size_type;
typedef T2ghz /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__from_precision_tag;
typedef uint32_t /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__from_size_type;
typedef uint32_t /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__upper_count_type;
typedef /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__from_precision_tag /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__precision_tag;
typedef /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__from_size_type /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__size_type;
typedef /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__to_precision_tag /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__Counter__precision_tag;
typedef /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__to_size_type /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__Counter__size_type;
typedef TMicro /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__precision_tag;
typedef /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__precision_tag /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__LocalTime__precision_tag;
typedef /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__precision_tag /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__precision_tag;
typedef uint32_t /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__size_type;
enum /*PlatformSerialC.UartC*/Msp430Uart1C__0____nesc_unnamed4313 {
  Msp430Uart1C__0__CLIENT_ID = 0U
};
typedef T32khz /*Msp430Uart1P.UartP*/Msp430UartP__0__Counter__precision_tag;
typedef uint16_t /*Msp430Uart1P.UartP*/Msp430UartP__0__Counter__size_type;
enum /*PlatformSerialC.UartC.UsartC*/Msp430Usart1C__0____nesc_unnamed4314 {
  Msp430Usart1C__0__CLIENT_ID = 0U
};
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t PlatformP__Init__init(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Platform.nc"
static uint32_t PlatformP__Platform__usecsRaw(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t MotePlatformC__Init__init(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/Msp430ClockInit.nc"
static void Msp430ClockP__Msp430ClockInit__defaultInitClocks(void );
#line 43
static void Msp430ClockP__Msp430ClockInit__default__initTimerB(void );



static void Msp430ClockP__Msp430ClockInit__defaultInitTimerA(void );
#line 42
static void Msp430ClockP__Msp430ClockInit__default__initTimerA(void );





static void Msp430ClockP__Msp430ClockInit__defaultInitTimerB(void );
#line 45
static void Msp430ClockP__Msp430ClockInit__defaultSetupDcoCalibrate(void );
#line 40
static void Msp430ClockP__Msp430ClockInit__default__setupDcoCalibrate(void );
static void Msp430ClockP__Msp430ClockInit__default__initClocks(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerOverride.nc"
static mcu_power_t Msp430ClockP__McuPowerOverride__lowestState(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t Msp430ClockP__Init__init(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuSleep.nc"
static void McuSleepC__McuSleep__sleep(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t SchedulerBasicP__TaskBasic__postTask(
# 55 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
uint8_t arg_0x7f2558a8f9c0);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void SchedulerBasicP__TaskBasic__default__runTask(
# 55 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
uint8_t arg_0x7f2558a8f9c0);
# 57 "/home/wtiberti/WSN/tinyos/tos/interfaces/Scheduler.nc"
static void SchedulerBasicP__Scheduler__init(void );
#line 72
static void SchedulerBasicP__Scheduler__taskLoop(void );
#line 65
static bool SchedulerBasicP__Scheduler__runNextTask(void );
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
# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static bool /*HplMsp430GeneralIOC.P10*/HplMsp430GeneralIOP__0__IO__get(void );
#line 67
static uint8_t /*HplMsp430GeneralIOC.P10*/HplMsp430GeneralIOP__0__IO__getRaw(void );






static bool /*HplMsp430GeneralIOC.P13*/HplMsp430GeneralIOP__3__IO__get(void );
#line 67
static uint8_t /*HplMsp430GeneralIOC.P13*/HplMsp430GeneralIOP__3__IO__getRaw(void );
#line 79
static void /*HplMsp430GeneralIOC.P14*/HplMsp430GeneralIOP__4__IO__makeInput(void );
#line 74
static bool /*HplMsp430GeneralIOC.P14*/HplMsp430GeneralIOP__4__IO__get(void );
#line 67
static uint8_t /*HplMsp430GeneralIOC.P14*/HplMsp430GeneralIOP__4__IO__getRaw(void );
#line 79
static void /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__makeInput(void );





static void /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__makeOutput(void );
#line 74
static bool /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__get(void );
#line 67
static uint8_t /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__getRaw(void );
#line 54
static void /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__clr(void );
#line 97
static void /*HplMsp430GeneralIOC.P31*/HplMsp430GeneralIOP__17__IO__selectIOFunc(void );
#line 91
static void /*HplMsp430GeneralIOC.P31*/HplMsp430GeneralIOP__17__IO__selectModuleFunc(void );





static void /*HplMsp430GeneralIOC.P32*/HplMsp430GeneralIOP__18__IO__selectIOFunc(void );
#line 91
static void /*HplMsp430GeneralIOC.P32*/HplMsp430GeneralIOP__18__IO__selectModuleFunc(void );





static void /*HplMsp430GeneralIOC.P33*/HplMsp430GeneralIOP__19__IO__selectIOFunc(void );
#line 91
static void /*HplMsp430GeneralIOC.P33*/HplMsp430GeneralIOP__19__IO__selectModuleFunc(void );





static void /*HplMsp430GeneralIOC.P34*/HplMsp430GeneralIOP__20__IO__selectIOFunc(void );
#line 97
static void /*HplMsp430GeneralIOC.P35*/HplMsp430GeneralIOP__21__IO__selectIOFunc(void );
#line 97
static void /*HplMsp430GeneralIOC.P36*/HplMsp430GeneralIOP__22__IO__selectIOFunc(void );
#line 91
static void /*HplMsp430GeneralIOC.P36*/HplMsp430GeneralIOP__22__IO__selectModuleFunc(void );





static void /*HplMsp430GeneralIOC.P37*/HplMsp430GeneralIOP__23__IO__selectIOFunc(void );
#line 91
static void /*HplMsp430GeneralIOC.P37*/HplMsp430GeneralIOP__23__IO__selectModuleFunc(void );
#line 79
static void /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__makeInput(void );
#line 74
static bool /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__get(void );
#line 97
static void /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__selectIOFunc(void );
#line 67
static uint8_t /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__getRaw(void );
#line 91
static void /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__selectModuleFunc(void );
#line 85
static void /*HplMsp430GeneralIOC.P42*/HplMsp430GeneralIOP__26__IO__makeOutput(void );
#line 49
static void /*HplMsp430GeneralIOC.P42*/HplMsp430GeneralIOP__26__IO__set(void );




static void /*HplMsp430GeneralIOC.P42*/HplMsp430GeneralIOP__26__IO__clr(void );
#line 85
static void /*HplMsp430GeneralIOC.P45*/HplMsp430GeneralIOP__29__IO__makeOutput(void );
#line 49
static void /*HplMsp430GeneralIOC.P45*/HplMsp430GeneralIOP__29__IO__set(void );




static void /*HplMsp430GeneralIOC.P45*/HplMsp430GeneralIOP__29__IO__clr(void );
#line 85
static void /*HplMsp430GeneralIOC.P46*/HplMsp430GeneralIOP__30__IO__makeOutput(void );
#line 49
static void /*HplMsp430GeneralIOC.P46*/HplMsp430GeneralIOP__30__IO__set(void );




static void /*HplMsp430GeneralIOC.P46*/HplMsp430GeneralIOP__30__IO__clr(void );
#line 97
static void /*HplMsp430GeneralIOC.P51*/HplMsp430GeneralIOP__33__IO__selectIOFunc(void );
#line 97
static void /*HplMsp430GeneralIOC.P52*/HplMsp430GeneralIOP__34__IO__selectIOFunc(void );
#line 97
static void /*HplMsp430GeneralIOC.P53*/HplMsp430GeneralIOP__35__IO__selectIOFunc(void );
#line 85
static void /*HplMsp430GeneralIOC.P54*/HplMsp430GeneralIOP__36__IO__makeOutput(void );
#line 49
static void /*HplMsp430GeneralIOC.P54*/HplMsp430GeneralIOP__36__IO__set(void );




static void /*HplMsp430GeneralIOC.P54*/HplMsp430GeneralIOP__36__IO__clr(void );
#line 85
static void /*HplMsp430GeneralIOC.P55*/HplMsp430GeneralIOP__37__IO__makeOutput(void );
#line 49
static void /*HplMsp430GeneralIOC.P55*/HplMsp430GeneralIOP__37__IO__set(void );




static void /*HplMsp430GeneralIOC.P55*/HplMsp430GeneralIOP__37__IO__clr(void );
#line 85
static void /*HplMsp430GeneralIOC.P56*/HplMsp430GeneralIOP__38__IO__makeOutput(void );
#line 49
static void /*HplMsp430GeneralIOC.P56*/HplMsp430GeneralIOP__38__IO__set(void );




static void /*HplMsp430GeneralIOC.P56*/HplMsp430GeneralIOP__38__IO__clr(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__GeneralIO__makeOutput(void );
#line 40
static void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__GeneralIO__set(void );
static void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__GeneralIO__clr(void );




static void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__GeneralIO__makeOutput(void );
#line 40
static void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__GeneralIO__set(void );
static void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__GeneralIO__clr(void );




static void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__GeneralIO__makeOutput(void );
#line 40
static void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__GeneralIO__set(void );
static void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__GeneralIO__clr(void );
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
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__VectorTimerX0__fired(void );
#line 39
static void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Overflow__fired(void );
#line 39
static void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__VectorTimerX1__fired(void );
#line 39
static void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Event__default__fired(
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
uint8_t arg_0x7f25584338b0);
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static uint16_t /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Timer__get(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__VectorTimerX0__fired(void );
#line 39
static void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Overflow__fired(void );
#line 39
static void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__VectorTimerX1__fired(void );
#line 39
static void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Event__default__fired(
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
uint8_t arg_0x7f25584338b0);
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static uint16_t /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__get(void );
static bool /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__isOverflowPending(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static uint16_t /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Capture__getEvent(void );
#line 92
static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Capture__default__captured(uint16_t time);
# 41 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static msp430_compare_control_t /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__getControl(void );
#line 76
static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__enableEvents(void );

static bool /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__areEventsEnabled(void );
#line 77
static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__disableEvents(void );
#line 43
static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__clearPendingInterrupt(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Event__fired(void );
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Compare__setEvent(uint16_t time);

static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Compare__setEventFromNow(uint16_t delta);
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Timer__overflow(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static uint16_t /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Capture__getEvent(void );
#line 92
static void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Capture__default__captured(uint16_t time);
# 41 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static msp430_compare_control_t /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Control__getControl(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Event__fired(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Compare__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Timer__overflow(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static uint16_t /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Capture__getEvent(void );
#line 92
static void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Capture__default__captured(uint16_t time);
# 41 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static msp430_compare_control_t /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Control__getControl(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Event__fired(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Compare__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Timer__overflow(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static uint16_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Capture__getEvent(void );
#line 92
static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Capture__default__captured(uint16_t time);
# 41 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static msp430_compare_control_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__getControl(void );
#line 76
static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__enableEvents(void );
#line 56
static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__setControlAsCompare(void );
#line 77
static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__disableEvents(void );
#line 43
static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__clearPendingInterrupt(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Event__fired(void );
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Compare__setEvent(uint16_t time);

static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Compare__setEventFromNow(uint16_t delta);
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Timer__overflow(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static uint16_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Capture__getEvent(void );
#line 74
static void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Capture__clearOverflow(void );
# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__setControlAsCapture(uint8_t cm, uint8_t ccis);
#line 41
static msp430_compare_control_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__getControl(void );
#line 76
static void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__enableEvents(void );
static void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__disableEvents(void );
#line 43
static void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__clearPendingInterrupt(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Event__fired(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Compare__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Timer__overflow(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static uint16_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Capture__getEvent(void );
#line 92
static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Capture__default__captured(uint16_t time);
# 41 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static msp430_compare_control_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__getControl(void );
#line 76
static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__enableEvents(void );
#line 56
static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__setControlAsCompare(void );
#line 77
static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__disableEvents(void );
#line 43
static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__clearPendingInterrupt(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Event__fired(void );
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Compare__setEvent(uint16_t time);

static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Compare__setEventFromNow(uint16_t delta);
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Timer__overflow(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static uint16_t /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Capture__getEvent(void );
#line 92
static void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Capture__default__captured(uint16_t time);
# 41 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static msp430_compare_control_t /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Control__getControl(void );
#line 77
static void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Control__disableEvents(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Event__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Timer__overflow(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static uint16_t /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Capture__getEvent(void );
#line 92
static void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Capture__default__captured(uint16_t time);
# 41 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static msp430_compare_control_t /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Control__getControl(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Event__fired(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Compare__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Timer__overflow(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static uint16_t /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Capture__getEvent(void );
#line 92
static void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Capture__default__captured(uint16_t time);
# 41 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static msp430_compare_control_t /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Control__getControl(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Event__fired(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Compare__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Timer__overflow(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static uint16_t /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Capture__getEvent(void );
#line 92
static void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Capture__default__captured(uint16_t time);
# 41 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static msp430_compare_control_t /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Control__getControl(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Event__fired(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Compare__default__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Timer__overflow(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Compare__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Timer__overflow(void );
# 103 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__startAt(/*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__size_type t0, /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__size_type dt);
#line 73
static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__stop(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Init__init(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Msp430Timer__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__size_type /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__get(void );






static bool /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__isOverflowPending(void );










static void /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__overflow(void );
#line 64
static /*CounterMilli32C.Transform*/TransformCounterC__0__Counter__size_type /*CounterMilli32C.Transform*/TransformCounterC__0__Counter__get(void );
# 109 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__getNow(void );
#line 103
static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__startAt(/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__size_type t0, /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__size_type dt);
#line 116
static /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__getAlarm(void );
#line 73
static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__stop(void );




static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__fired(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Counter__overflow(void );
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
uint8_t arg_0x7f2558216ca0);
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Timer.nc"
static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__startPeriodic(
# 63 "/home/wtiberti/WSN/tinyos/tos/lib/timer/VirtualizeTimerImplP.nc"
uint8_t arg_0x7f2558216ca0, 
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
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Compare__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Timer__overflow(void );
# 103 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__size_type t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__size_type dt);
#line 73
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__stop(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Init__init(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__overflow(void );
#line 64
static /*Counter32khz32C.Transform*/TransformCounterC__1__Counter__size_type /*Counter32khz32C.Transform*/TransformCounterC__1__Counter__get(void );
# 109 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__getNow(void );
#line 103
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__size_type t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__size_type dt);
#line 66
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__start(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__size_type dt);






static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__stop(void );




static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__fired(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Counter__overflow(void );
# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__GeneralIO__makeInput(void );
#line 43
static bool /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__GeneralIO__get(void );


static void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__makeOutput(void );
#line 40
static void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__set(void );
static void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__clr(void );

static bool /*HplCC2420PinsC.FIFOM*/Msp430GpioC__5__GeneralIO__get(void );
#line 43
static bool /*HplCC2420PinsC.FIFOPM*/Msp430GpioC__6__GeneralIO__get(void );


static void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__GeneralIO__makeOutput(void );
#line 40
static void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__GeneralIO__set(void );
static void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__GeneralIO__clr(void );


static void /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__GeneralIO__makeInput(void );
#line 43
static bool /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__GeneralIO__get(void );


static void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__GeneralIO__makeOutput(void );
#line 40
static void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__GeneralIO__set(void );
static void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__GeneralIO__clr(void );
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430Capture__captured(uint16_t time);
# 54 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
static error_t /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__captureFallingEdge(void );
#line 66
static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__disable(void );
#line 53
static error_t /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__captureRisingEdge(void );
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
static void HplMsp430InterruptP__Port14__clear(void );
#line 49
static void HplMsp430InterruptP__Port14__disable(void );
#line 44
static void HplMsp430InterruptP__Port14__enable(void );
#line 66
static void HplMsp430InterruptP__Port14__edgeRising(void );
#line 54
static void HplMsp430InterruptP__Port26__clear(void );
#line 85
static void HplMsp430InterruptP__Port26__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port17__clear(void );
#line 85
static void HplMsp430InterruptP__Port17__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port21__clear(void );
#line 85
static void HplMsp430InterruptP__Port21__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port12__clear(void );
#line 85
static void HplMsp430InterruptP__Port12__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port24__clear(void );
#line 85
static void HplMsp430InterruptP__Port24__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port15__clear(void );
#line 85
static void HplMsp430InterruptP__Port15__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port27__clear(void );
#line 85
static void HplMsp430InterruptP__Port27__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port10__clear(void );
#line 49
static void HplMsp430InterruptP__Port10__disable(void );
#line 67
static void HplMsp430InterruptP__Port10__edgeFalling(void );
#line 44
static void HplMsp430InterruptP__Port10__enable(void );









static void HplMsp430InterruptP__Port22__clear(void );
#line 85
static void HplMsp430InterruptP__Port22__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port13__clear(void );
#line 85
static void HplMsp430InterruptP__Port13__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port25__clear(void );
#line 85
static void HplMsp430InterruptP__Port25__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port16__clear(void );
#line 85
static void HplMsp430InterruptP__Port16__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port20__clear(void );
#line 85
static void HplMsp430InterruptP__Port20__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port11__clear(void );
#line 85
static void HplMsp430InterruptP__Port11__default__fired(void );
#line 54
static void HplMsp430InterruptP__Port23__clear(void );
#line 85
static void HplMsp430InterruptP__Port23__default__fired(void );
#line 85
static void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__fired(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
static error_t /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__Interrupt__disable(void );
#line 53
static error_t /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__Interrupt__enableRisingEdge(void );
# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__fired(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
static error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__Interrupt__disable(void );
#line 54
static error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__Interrupt__enableFallingEdge(void );
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
uint8_t arg_0x7f2557d946e0, 
# 62 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
uint8_t * data, uint8_t length);
#line 91
static void CC2420SpiP__Fifo__default__writeDone(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d946e0, 
# 91 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
uint8_t * data, uint8_t length, error_t error);
#line 82
static cc2420_status_t CC2420SpiP__Fifo__write(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d946e0, 
# 82 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
uint8_t * data, uint8_t length);
#line 51
static cc2420_status_t CC2420SpiP__Fifo__beginRead(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d946e0, 
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
uint8_t * data, uint8_t length);
#line 71
static void CC2420SpiP__Fifo__default__readDone(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d946e0, 
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
uint16_t arg_0x7f2557d939f0, 
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Ram.nc"
uint8_t offset, uint8_t * data, uint8_t length);
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
static cc2420_status_t CC2420SpiP__Reg__read(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d91880, 
# 55 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
uint16_t *data);







static cc2420_status_t CC2420SpiP__Reg__write(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d91880, 
# 63 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Register.nc"
uint16_t data);
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420SpiP__Resource__release(
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d95360);
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420SpiP__Resource__immediateRequest(
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d95360);
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420SpiP__Resource__request(
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d95360);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420SpiP__Resource__default__granted(
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d95360);
# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static bool CC2420SpiP__Resource__isOwner(
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d95360);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void CC2420SpiP__grant__runTask(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Strobe.nc"
static cc2420_status_t CC2420SpiP__Strobe__strobe(
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d90700);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t StateImplP__Init__init(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
static void StateImplP__State__toIdle(
# 67 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
uint8_t arg_0x7f2557d1a9c0);
# 66 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
static bool StateImplP__State__isState(
# 67 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
uint8_t arg_0x7f2557d1a9c0, 
# 66 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
uint8_t myState);
#line 61
static bool StateImplP__State__isIdle(
# 67 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
uint8_t arg_0x7f2557d1a9c0);
# 45 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
static error_t StateImplP__State__requestState(
# 67 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
uint8_t arg_0x7f2557d1a9c0, 
# 45 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
uint8_t reqState);





static void StateImplP__State__forceState(
# 67 "/home/wtiberti/WSN/tinyos/tos/system/StateImplP.nc"
uint8_t arg_0x7f2557d1a9c0, 
# 51 "/home/wtiberti/WSN/tinyos/tos/interfaces/State.nc"
uint8_t reqState);
# 65 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__ResourceConfigure__unconfigure(
# 76 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8ea10);
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__ResourceConfigure__configure(
# 76 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8ea10);
# 76 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiPacket__send(
# 79 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8bb50, 
# 65 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
uint8_t * txBuf, 

uint8_t * rxBuf, 








uint16_t len);
#line 88
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiPacket__default__sendDone(
# 79 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8bb50, 
# 81 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
uint8_t * txBuf, 
uint8_t * rxBuf, 





uint16_t len, 
error_t error);
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiConfigure.nc"
static const msp430_spi_union_config_t */*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Msp430SpiConfigure__default__getConfig(
# 82 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c89d40);
# 45 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiByte.nc"
static uint8_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiByte__write(uint8_t tx);
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__release(
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8a980);
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__immediateRequest(
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8a980);
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__request(
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8a980);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__granted(
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8a980);
# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static bool /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__isOwner(
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8a980);
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__release(
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8f770);
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__immediateRequest(
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8f770);
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__request(
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8f770);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__default__granted(
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8f770);
# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static bool /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__isOwner(
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8f770);
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartInterrupts__rxDone(uint8_t data);
#line 49
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartInterrupts__txDone(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone_task__runTask(void );
# 180 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
static void HplMsp430Usart0P__Usart__enableRxIntr(void );
#line 197
static void HplMsp430Usart0P__Usart__clrRxIntr(void );
#line 97
static void HplMsp430Usart0P__Usart__resetUsart(bool reset);
#line 179
static void HplMsp430Usart0P__Usart__disableIntr(void );
#line 90
static void HplMsp430Usart0P__Usart__setUmctl(uint8_t umctl);
#line 177
static void HplMsp430Usart0P__Usart__disableRxIntr(void );
#line 207
static void HplMsp430Usart0P__Usart__clrIntr(void );
#line 80
static void HplMsp430Usart0P__Usart__setUbr(uint16_t ubr);
#line 220
static void HplMsp430Usart0P__Usart__tx(uint8_t data);
#line 128
static void HplMsp430Usart0P__Usart__disableUart(void );
#line 153
static void HplMsp430Usart0P__Usart__enableSpi(void );
#line 168
static void HplMsp430Usart0P__Usart__setModeSpi(const msp430_spi_union_config_t *config);
#line 227
static uint8_t HplMsp430Usart0P__Usart__rx(void );
#line 192
static bool HplMsp430Usart0P__Usart__isRxIntrPending(void );
#line 158
static void HplMsp430Usart0P__Usart__disableSpi(void );
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
static void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__default__rxDone(
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
uint8_t arg_0x7f2557b16cd0, 
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
uint8_t data);
#line 49
static void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__default__txDone(
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
uint8_t arg_0x7f2557b16cd0);
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430I2CInterrupts.nc"
static void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__RawI2CInterrupts__fired(void );
#line 39
static void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__I2CInterrupts__default__fired(
# 40 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
uint8_t arg_0x7f2557b15b80);
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
static void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__RawInterrupts__rxDone(uint8_t data);
#line 49
static void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__RawInterrupts__txDone(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__Init__init(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
static error_t /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__enqueue(resource_client_id_t id);
#line 53
static bool /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEmpty(void );








static bool /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEnqueued(resource_client_id_t id);







static resource_client_id_t /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__dequeue(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__default__requested(
# 99 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad49d0);
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__default__immediateRequested(
# 99 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad49d0);
# 65 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__default__unconfigure(
# 105 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad06b0);
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__default__configure(
# 105 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad06b0);
# 54 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwner.nc"
static error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__release(void );
#line 71
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__default__requested(void );
#line 44
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__default__granted(void );
#line 79
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__default__immediateRequested(void );
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__release(
# 98 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad56a0);
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__immediateRequest(
# 98 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad56a0);
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__request(
# 98 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad56a0);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__default__granted(
# 98 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad56a0);
# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__isOwner(
# 98 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad56a0);
# 9 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwnerInfo.nc"
static bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwnerInfo__default__inUse(void );
# 90 "/home/wtiberti/WSN/tinyos/tos/interfaces/ArbiterInfo.nc"
static bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ArbiterInfo__inUse(void );







static uint8_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ArbiterInfo__userId(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__grantedTask__runTask(void );
# 7 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430I2C.nc"
static void HplMsp430I2C0P__HplI2C__clearModeI2C(void );
#line 6
static bool HplMsp430I2C0P__HplI2C__isI2C(void );
# 55 "/home/wtiberti/WSN/tinyos/tos/system/ActiveMessageAddressC.nc"
static am_addr_t ActiveMessageAddressC__amAddress(void );
# 50 "/home/wtiberti/WSN/tinyos/tos/interfaces/ActiveMessageAddress.nc"
static am_addr_t ActiveMessageAddressC__ActiveMessageAddress__amAddress(void );




static am_group_t ActiveMessageAddressC__ActiveMessageAddress__amGroup(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/interfaces/LocalIeeeEui64.nc"
static ieee_eui64_t LocalIeeeEui64P__LocalIeeeEui64__getId(void );
# 13 "/home/wtiberti/WSN/tinyos/tos/chips/ds2411/ReadId48.nc"
static error_t Ds2411P__ReadId48__read(uint8_t *id);
# 10 "/home/wtiberti/WSN/tinyos/tos/lib/onewire/OneWireReadWrite.nc"
static error_t OneWireMasterP__OneWire__read(uint8_t cmd, uint8_t *buf, uint8_t len);
# 66 "/home/wtiberti/WSN/tinyos/tos/lib/timer/BusyWait.nc"
static void /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__BusyWait__wait(/*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__BusyWait__size_type dt);
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__overflow(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Msp430Timer__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Counter__size_type /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Counter__get(void );
# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__makeInput(void );
#line 43
static bool /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__get(void );


static void /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__makeOutput(void );
#line 41
static void /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__clr(void );
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t Ds2411PowerControlC__StdControl__start(void );









static error_t Ds2411PowerControlC__StdControl__stop(void );
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
uint8_t arg_0x7f255758f600);
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420TinyosNetworkP__Resource__immediateRequest(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
uint8_t arg_0x7f255758f600);
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t CC2420TinyosNetworkP__Resource__request(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
uint8_t arg_0x7f255758f600);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void CC2420TinyosNetworkP__Resource__default__granted(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/lowpan/CC2420TinyosNetworkP.nc"
uint8_t arg_0x7f255758f600);
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
am_id_t arg_0x7f25574f8700, 
# 95 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
message_t * msg);
#line 81
static void CC2420ActiveMessageP__RadioBackoff__default__requestInitialBackoff(
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f25574f8700, 
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
message_t * msg);






static void CC2420ActiveMessageP__RadioBackoff__default__requestCongestionBackoff(
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f25574f8700, 
# 88 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
message_t * msg);
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/SendNotifier.nc"
static void CC2420ActiveMessageP__SendNotifier__default__aboutToSend(
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f25574f9b30, 
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
am_id_t arg_0x7f2557501cf0, 
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
am_id_t arg_0x7f25574fcc40, 
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
am_id_t arg_0x7f25574fc060, 
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
am_id_t arg_0x7f2557435510, 
# 103 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
message_t * msg, 






error_t error);
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static error_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__send(
# 47 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
uint8_t arg_0x7f2557438960, 
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
message_t * msg, 







uint8_t len);
#line 100
static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__default__sendDone(
# 47 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
uint8_t arg_0x7f2557438960, 
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
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void Msp430HybridAlarmCounterP__CounterMicro__overflow(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerOverride.nc"
static mcu_power_t Msp430HybridAlarmCounterP__McuPowerOverride__lowestState(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static Msp430HybridAlarmCounterP__Counter2ghz__size_type Msp430HybridAlarmCounterP__Counter2ghz__get(void );






static bool Msp430HybridAlarmCounterP__Counter2ghz__isOverflowPending(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void Msp430HybridAlarmCounterP__Alarm32khz__fired(void );
#line 78
static void Msp430HybridAlarmCounterP__Alarm2ghz__default__fired(void );
#line 78
static void Msp430HybridAlarmCounterP__AlarmMicro__fired(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void Msp430HybridAlarmCounterP__Counter32khz__overflow(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Msp430Compare__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Msp430Timer__overflow(void );
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Compare__fired(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Timer__overflow(void );
# 103 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__startAt(/*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__size_type t0, /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__size_type dt);
#line 88
static bool /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__isRunning(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__overflow(void );
#line 64
static /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__Counter__size_type /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__Counter__get(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/lib/timer/LocalTime.nc"
static uint32_t /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__LocalTime__get(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__overflow(void );
# 49 "/home/wtiberti/WSN/tinyos/tos/lib/printf/Putchar.nc"
static int SerialPrintfP__Putchar__putchar(int c);
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t SerialPrintfP__Init__init(void );
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t SerialPrintfP__StdControl__start(void );
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__ResourceConfigure__configure(
# 47 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f25572696f0);
# 50 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartByte.nc"
static error_t /*Msp430Uart1P.UartP*/Msp430UartP__0__UartByte__send(
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f2557266b50, 
# 50 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartByte.nc"
uint8_t byte);
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartConfigure.nc"
static const msp430_uart_union_config_t */*Msp430Uart1P.UartP*/Msp430UartP__0__Msp430UartConfigure__default__getConfig(
# 52 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f2557262020);
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__default__receivedByte(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f25572674c0, 
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
uint8_t byte);
#line 99
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__default__receiveDone(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f25572674c0, 
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
uint8_t * buf, 



uint16_t len, error_t error);
#line 57
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__default__sendDone(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f25572674c0, 
# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
uint8_t * buf, 



uint16_t len, error_t error);
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Counter__overflow(void );
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__default__immediateRequest(
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f2557265ca0);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__granted(
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f2557265ca0);
# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static bool /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__default__isOwner(
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f2557265ca0);
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430Uart1P.UartP*/Msp430UartP__0__Resource__immediateRequest(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f255726a410);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Resource__default__granted(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f255726a410);
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartInterrupts__rxDone(
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f255725d820, 
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
uint8_t data);
#line 49
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartInterrupts__txDone(
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f255725d820);
# 143 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
static void HplMsp430Usart1P__Usart__enableUartRx(void );
#line 123
static void HplMsp430Usart1P__Usart__enableUart(void );
#line 97
static void HplMsp430Usart1P__Usart__resetUsart(bool reset);
#line 179
static void HplMsp430Usart1P__Usart__disableIntr(void );

static void HplMsp430Usart1P__Usart__enableTxIntr(void );
#line 90
static void HplMsp430Usart1P__Usart__setUmctl(uint8_t umctl);
#line 133
static void HplMsp430Usart1P__Usart__enableUartTx(void );
#line 178
static void HplMsp430Usart1P__Usart__disableTxIntr(void );
#line 148
static void HplMsp430Usart1P__Usart__disableUartRx(void );
#line 182
static void HplMsp430Usart1P__Usart__enableIntr(void );




static bool HplMsp430Usart1P__Usart__isTxIntrPending(void );
#line 207
static void HplMsp430Usart1P__Usart__clrIntr(void );
#line 80
static void HplMsp430Usart1P__Usart__setUbr(uint16_t ubr);
#line 220
static void HplMsp430Usart1P__Usart__tx(uint8_t data);
#line 128
static void HplMsp430Usart1P__Usart__disableUart(void );
#line 174
static void HplMsp430Usart1P__Usart__setModeUart(const msp430_uart_union_config_t *config);
#line 202
static void HplMsp430Usart1P__Usart__clrTxIntr(void );
#line 158
static void HplMsp430Usart1P__Usart__disableSpi(void );
#line 138
static void HplMsp430Usart1P__Usart__disableUartTx(void );
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/AsyncStdControl.nc"
static error_t HplMsp430Usart1P__AsyncStdControl__start(void );
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
static void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__default__rxDone(
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
uint8_t arg_0x7f2557b16cd0, 
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
uint8_t data);
#line 49
static void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__default__txDone(
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
uint8_t arg_0x7f2557b16cd0);
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
static void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__RawInterrupts__rxDone(uint8_t data);
#line 49
static void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__RawInterrupts__txDone(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t /*Msp430UsartShare1P.ArbiterC.Queue*/FcfsResourceQueueC__2__Init__init(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
static void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceRequested__default__immediateRequested(
# 99 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad49d0);
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceConfigure__default__configure(
# 105 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad06b0);
# 54 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwner.nc"
static error_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwner__release(void );
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__immediateRequest(
# 98 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad56a0);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__default__granted(
# 98 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad56a0);
# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static bool /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__isOwner(
# 98 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad56a0);
# 9 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwnerInfo.nc"
static bool /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwnerInfo__default__inUse(void );
# 90 "/home/wtiberti/WSN/tinyos/tos/interfaces/ArbiterInfo.nc"
static bool /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ArbiterInfo__inUse(void );







static uint8_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ArbiterInfo__userId(void );
# 75 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__grantedTask__runTask(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwner.nc"
static void /*Msp430UsartShare1P.PowerManagerC.PowerManager*/AsyncPowerManagerP__0__ResourceDefaultOwner__immediateRequested(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartConfigure.nc"
static const msp430_uart_union_config_t *TelosSerialP__Msp430UartConfigure__getConfig(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void TelosSerialP__Resource__granted(void );
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t TelosSerialP__StdControl__start(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
static error_t PutcharP__Init__init(void );
#line 62
static error_t PlatformP__MoteInit__init(void );
#line 62
static error_t PlatformP__MoteClockInit__init(void );
#line 62
static error_t PlatformP__LedsInit__init(void );
# 11 "/home/wtiberti/WSN/tinyos/tos/platforms/telosa/PlatformP.nc"
static inline error_t PlatformP__Init__init(void );








static inline uint32_t PlatformP__Platform__usecsRaw(void );
# 6 "/home/wtiberti/WSN/tinyos/tos/platforms/telosb/MotePlatformC.nc"
static __inline void MotePlatformC__uwait(uint16_t u);




static __inline void MotePlatformC__TOSH_wait(void );




static void MotePlatformC__TOSH_FLASH_M25P_DP_bit(bool set);










static inline void MotePlatformC__TOSH_FLASH_M25P_DP(void );
#line 56
static inline error_t MotePlatformC__Init__init(void );
# 43 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/Msp430ClockInit.nc"
static void Msp430ClockP__Msp430ClockInit__initTimerB(void );
#line 42
static void Msp430ClockP__Msp430ClockInit__initTimerA(void );
#line 40
static void Msp430ClockP__Msp430ClockInit__setupDcoCalibrate(void );
static void Msp430ClockP__Msp430ClockInit__initClocks(void );
# 209 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/clock_bcs/Msp430ClockP.nc"
extern volatile uint8_t Msp430ClockP__IE1 __asm ("IE1");
extern volatile uint16_t Msp430ClockP__TACTL __asm ("TACTL");

extern volatile uint16_t Msp430ClockP__TBCTL __asm ("TBCTL");










enum Msp430ClockP____nesc_unnamed4315 {
  Msp430ClockP__ACLK_CALIB_PERIOD = 8, 
  Msp430ClockP__TARGET_DCO_DELTA = 4194304UL / 32768UL * Msp430ClockP__ACLK_CALIB_PERIOD
};

static inline mcu_power_t Msp430ClockP__McuPowerOverride__lowestState(void );



static inline void Msp430ClockP__Msp430ClockInit__defaultSetupDcoCalibrate(void );
#line 253
static inline void Msp430ClockP__Msp430ClockInit__defaultInitClocks(void );
#line 275
static inline void Msp430ClockP__Msp430ClockInit__defaultInitTimerA(void );
#line 287
static inline void Msp430ClockP__Msp430ClockInit__defaultInitTimerB(void );
#line 301
static inline void Msp430ClockP__Msp430ClockInit__default__setupDcoCalibrate(void );



static inline void Msp430ClockP__Msp430ClockInit__default__initClocks(void );



static inline void Msp430ClockP__Msp430ClockInit__default__initTimerA(void );



static inline void Msp430ClockP__Msp430ClockInit__default__initTimerB(void );



static inline void Msp430ClockP__startTimerA(void );









static inline void Msp430ClockP__startTimerB(void );
#line 367
static void Msp430ClockP__set_dco_calib(uint16_t calib);




static inline uint16_t Msp430ClockP__test_calib_busywait_delta(uint16_t calib);
#line 408
static inline void Msp430ClockP__busyCalibrateDco(void );
#line 433
static inline error_t Msp430ClockP__Init__init(void );
# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerOverride.nc"
static mcu_power_t McuSleepC__McuPowerOverride__lowestState(void );
# 60 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1xxx/McuSleepC.nc"
extern volatile uint8_t McuSleepC__U0CTLnr __asm ("U0CTL");
extern volatile uint8_t McuSleepC__I2CTCTLnr __asm ("I2CTCTL");
extern volatile uint8_t McuSleepC__I2CDCTLnr __asm ("I2CDCTL");

bool McuSleepC__dirty = TRUE;
mcu_power_t McuSleepC__powerState = MSP430_POWER_ACTIVE;




const uint16_t McuSleepC__msp430PowerBits[MSP430_POWER_LPM4 + 1] = { 
0, 
0x0010, 
0x0040 + 0x0010, 
0x0080 + 0x0010, 
0x0080 + 0x0040 + 0x0010, 
0x0080 + 0x0040 + 0x0020 + 0x0010 };


static inline mcu_power_t McuSleepC__getPowerState(void );
#line 119
static inline void McuSleepC__computePowerState(void );




static inline void McuSleepC__McuSleep__sleep(void );
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
uint8_t arg_0x7f2558a8f9c0);
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuSleep.nc"
static void SchedulerBasicP__McuSleep__sleep(void );
# 59 "/home/wtiberti/WSN/tinyos/tos/system/SchedulerBasicP.nc"
enum SchedulerBasicP____nesc_unnamed4316 {
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
# 98 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline uint8_t /*HplMsp430GeneralIOC.P10*/HplMsp430GeneralIOP__0__IO__getRaw(void );
static inline bool /*HplMsp430GeneralIOC.P10*/HplMsp430GeneralIOP__0__IO__get(void );
#line 98
static inline uint8_t /*HplMsp430GeneralIOC.P13*/HplMsp430GeneralIOP__3__IO__getRaw(void );
static inline bool /*HplMsp430GeneralIOC.P13*/HplMsp430GeneralIOP__3__IO__get(void );
#line 98
static inline uint8_t /*HplMsp430GeneralIOC.P14*/HplMsp430GeneralIOP__4__IO__getRaw(void );
static inline bool /*HplMsp430GeneralIOC.P14*/HplMsp430GeneralIOP__4__IO__get(void );
static inline void /*HplMsp430GeneralIOC.P14*/HplMsp430GeneralIOP__4__IO__makeInput(void );
#line 96
static inline void /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__clr(void );

static inline uint8_t /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__getRaw(void );
static inline bool /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__get(void );
static inline void /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__makeInput(void );

static inline void /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__makeOutput(void );

static inline void /*HplMsp430GeneralIOC.P31*/HplMsp430GeneralIOP__17__IO__selectModuleFunc(void );

static inline void /*HplMsp430GeneralIOC.P31*/HplMsp430GeneralIOP__17__IO__selectIOFunc(void );
#line 104
static inline void /*HplMsp430GeneralIOC.P32*/HplMsp430GeneralIOP__18__IO__selectModuleFunc(void );

static inline void /*HplMsp430GeneralIOC.P32*/HplMsp430GeneralIOP__18__IO__selectIOFunc(void );
#line 104
static inline void /*HplMsp430GeneralIOC.P33*/HplMsp430GeneralIOP__19__IO__selectModuleFunc(void );

static inline void /*HplMsp430GeneralIOC.P33*/HplMsp430GeneralIOP__19__IO__selectIOFunc(void );
#line 106
static inline void /*HplMsp430GeneralIOC.P34*/HplMsp430GeneralIOP__20__IO__selectIOFunc(void );
#line 106
static inline void /*HplMsp430GeneralIOC.P35*/HplMsp430GeneralIOP__21__IO__selectIOFunc(void );
#line 104
static inline void /*HplMsp430GeneralIOC.P36*/HplMsp430GeneralIOP__22__IO__selectModuleFunc(void );

static inline void /*HplMsp430GeneralIOC.P36*/HplMsp430GeneralIOP__22__IO__selectIOFunc(void );
#line 104
static inline void /*HplMsp430GeneralIOC.P37*/HplMsp430GeneralIOP__23__IO__selectModuleFunc(void );

static inline void /*HplMsp430GeneralIOC.P37*/HplMsp430GeneralIOP__23__IO__selectIOFunc(void );
#line 98
static inline uint8_t /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__getRaw(void );
static inline bool /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__get(void );
static inline void /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__makeInput(void );



static inline void /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__selectModuleFunc(void );

static inline void /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__selectIOFunc(void );
#line 95
static void /*HplMsp430GeneralIOC.P42*/HplMsp430GeneralIOP__26__IO__set(void );
static void /*HplMsp430GeneralIOC.P42*/HplMsp430GeneralIOP__26__IO__clr(void );





static inline void /*HplMsp430GeneralIOC.P42*/HplMsp430GeneralIOP__26__IO__makeOutput(void );
#line 95
static inline void /*HplMsp430GeneralIOC.P45*/HplMsp430GeneralIOP__29__IO__set(void );
static inline void /*HplMsp430GeneralIOC.P45*/HplMsp430GeneralIOP__29__IO__clr(void );





static inline void /*HplMsp430GeneralIOC.P45*/HplMsp430GeneralIOP__29__IO__makeOutput(void );
#line 95
static void /*HplMsp430GeneralIOC.P46*/HplMsp430GeneralIOP__30__IO__set(void );
static void /*HplMsp430GeneralIOC.P46*/HplMsp430GeneralIOP__30__IO__clr(void );





static inline void /*HplMsp430GeneralIOC.P46*/HplMsp430GeneralIOP__30__IO__makeOutput(void );



static inline void /*HplMsp430GeneralIOC.P51*/HplMsp430GeneralIOP__33__IO__selectIOFunc(void );
#line 106
static inline void /*HplMsp430GeneralIOC.P52*/HplMsp430GeneralIOP__34__IO__selectIOFunc(void );
#line 106
static inline void /*HplMsp430GeneralIOC.P53*/HplMsp430GeneralIOP__35__IO__selectIOFunc(void );
#line 95
static void /*HplMsp430GeneralIOC.P54*/HplMsp430GeneralIOP__36__IO__set(void );
static void /*HplMsp430GeneralIOC.P54*/HplMsp430GeneralIOP__36__IO__clr(void );





static inline void /*HplMsp430GeneralIOC.P54*/HplMsp430GeneralIOP__36__IO__makeOutput(void );
#line 95
static void /*HplMsp430GeneralIOC.P55*/HplMsp430GeneralIOP__37__IO__set(void );
static inline void /*HplMsp430GeneralIOC.P55*/HplMsp430GeneralIOP__37__IO__clr(void );





static inline void /*HplMsp430GeneralIOC.P55*/HplMsp430GeneralIOP__37__IO__makeOutput(void );
#line 95
static void /*HplMsp430GeneralIOC.P56*/HplMsp430GeneralIOP__38__IO__set(void );
static inline void /*HplMsp430GeneralIOC.P56*/HplMsp430GeneralIOP__38__IO__clr(void );





static inline void /*HplMsp430GeneralIOC.P56*/HplMsp430GeneralIOP__38__IO__makeOutput(void );
# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__HplGeneralIO__makeOutput(void );
#line 49
static void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__HplGeneralIO__set(void );




static void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__HplGeneralIO__clr(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__GeneralIO__set(void );
static inline void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__GeneralIO__clr(void );




static inline void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__GeneralIO__makeOutput(void );
# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__HplGeneralIO__makeOutput(void );
#line 49
static void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__HplGeneralIO__set(void );




static void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__HplGeneralIO__clr(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__GeneralIO__set(void );
static inline void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__GeneralIO__clr(void );




static inline void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__GeneralIO__makeOutput(void );
# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__HplGeneralIO__makeOutput(void );
#line 49
static void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__HplGeneralIO__set(void );




static void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__HplGeneralIO__clr(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__GeneralIO__set(void );
static inline void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__GeneralIO__clr(void );




static inline void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__GeneralIO__makeOutput(void );
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
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Event__fired(
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
uint8_t arg_0x7f25584338b0);
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Timer__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
static inline uint16_t /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Timer__get(void );
#line 144
static inline void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__VectorTimerX0__fired(void );
#line 157
static inline void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__VectorTimerX1__fired(void );




static inline void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Overflow__fired(void );





static inline void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Event__default__fired(uint8_t n);
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Event__fired(
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
uint8_t arg_0x7f25584338b0);
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
static uint16_t /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__get(void );
#line 91
static inline bool /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__isOverflowPending(void );
#line 144
static inline void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__VectorTimerX0__fired(void );
#line 157
static inline void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__VectorTimerX1__fired(void );




static inline void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Overflow__fired(void );





static void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Event__default__fired(uint8_t n);
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Capture__captured(uint16_t time);
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Compare__fired(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static uint16_t /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Timer__get(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
typedef msp430_compare_control_t /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__cc_t;


static inline /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__cc_t /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__int2CC(uint16_t x)  ;
#line 84
static inline /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__cc_t /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__getControl(void );







static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__clearPendingInterrupt(void );
#line 109
static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__enableEvents(void );



static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__disableEvents(void );



static inline bool /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__areEventsEnabled(void );
#line 136
static inline uint16_t /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Capture__getEvent(void );



static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Compare__setEvent(uint16_t x);







static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Compare__setEventFromNow(uint16_t delta);
#line 160
static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Event__fired(void );






static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Capture__default__captured(uint16_t n);



static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Timer__overflow(void );
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Capture__captured(uint16_t time);
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Compare__fired(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
typedef msp430_compare_control_t /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__cc_t;


static inline /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__cc_t /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__int2CC(uint16_t x)  ;
#line 84
static inline /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__cc_t /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Control__getControl(void );
#line 136
static inline uint16_t /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Capture__getEvent(void );
#line 160
static void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Event__fired(void );






static inline void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Capture__default__captured(uint16_t n);

static inline void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Compare__default__fired(void );

static inline void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Timer__overflow(void );
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Capture__captured(uint16_t time);
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Compare__fired(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
typedef msp430_compare_control_t /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__cc_t;


static inline /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__cc_t /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__int2CC(uint16_t x)  ;
#line 84
static inline /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__cc_t /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Control__getControl(void );
#line 136
static inline uint16_t /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Capture__getEvent(void );
#line 160
static void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Event__fired(void );






static inline void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Capture__default__captured(uint16_t n);

static inline void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Compare__default__fired(void );

static inline void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Timer__overflow(void );
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Capture__captured(uint16_t time);
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Compare__fired(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static uint16_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Timer__get(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
typedef msp430_compare_control_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__cc_t;

static inline uint16_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__CC2int(/*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__cc_t x)  ;
static inline /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__cc_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__int2CC(uint16_t x)  ;
#line 72
static inline uint16_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__capComControl(uint8_t l_cm, uint8_t ccis, uint8_t cap_val);
#line 84
static inline /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__cc_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__getControl(void );







static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__clearPendingInterrupt(void );







static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__setControlAsCompare(void );








static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__enableEvents(void );



static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__disableEvents(void );
#line 136
static inline uint16_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Capture__getEvent(void );



static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Compare__setEvent(uint16_t x);







static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Compare__setEventFromNow(uint16_t delta);
#line 160
static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Event__fired(void );






static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Capture__default__captured(uint16_t n);



static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Timer__overflow(void );
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Capture__captured(uint16_t time);
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Compare__fired(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
typedef msp430_compare_control_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__cc_t;

static inline uint16_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__CC2int(/*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__cc_t x)  ;
static inline /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__cc_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__int2CC(uint16_t x)  ;
#line 72
static inline uint16_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__capComControl(uint8_t l_cm, uint8_t ccis, uint8_t cap_val);
#line 84
static inline /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__cc_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__getControl(void );







static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__clearPendingInterrupt(void );
#line 105
static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__setControlAsCapture(uint8_t cm, uint8_t ccis);



static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__enableEvents(void );



static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__disableEvents(void );
#line 136
static inline uint16_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Capture__getEvent(void );
#line 156
static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Capture__clearOverflow(void );



static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Event__fired(void );








static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Compare__default__fired(void );

static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Timer__overflow(void );
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Capture__captured(uint16_t time);
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Compare__fired(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static uint16_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Timer__get(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
typedef msp430_compare_control_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__cc_t;

static inline uint16_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__CC2int(/*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__cc_t x)  ;
static inline /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__cc_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__int2CC(uint16_t x)  ;
#line 72
static inline uint16_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__capComControl(uint8_t l_cm, uint8_t ccis, uint8_t cap_val);
#line 84
static inline /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__cc_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__getControl(void );







static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__clearPendingInterrupt(void );







static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__setControlAsCompare(void );








static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__enableEvents(void );



static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__disableEvents(void );
#line 136
static inline uint16_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Capture__getEvent(void );



static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Compare__setEvent(uint16_t x);







static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Compare__setEventFromNow(uint16_t delta);
#line 160
static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Event__fired(void );






static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Capture__default__captured(uint16_t n);



static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Timer__overflow(void );
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Capture__captured(uint16_t time);
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Compare__fired(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
typedef msp430_compare_control_t /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__cc_t;


static inline /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__cc_t /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__int2CC(uint16_t x)  ;
#line 84
static inline /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__cc_t /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Control__getControl(void );
#line 113
static inline void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Control__disableEvents(void );
#line 136
static inline uint16_t /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Capture__getEvent(void );
#line 160
static inline void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Event__fired(void );






static inline void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Capture__default__captured(uint16_t n);



static inline void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Timer__overflow(void );
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Capture__captured(uint16_t time);
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Compare__fired(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
typedef msp430_compare_control_t /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__cc_t;


static inline /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__cc_t /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__int2CC(uint16_t x)  ;
#line 84
static inline /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__cc_t /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Control__getControl(void );
#line 136
static inline uint16_t /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Capture__getEvent(void );
#line 160
static inline void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Event__fired(void );






static inline void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Capture__default__captured(uint16_t n);

static inline void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Compare__default__fired(void );

static inline void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Timer__overflow(void );
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Capture__captured(uint16_t time);
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Compare__fired(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
typedef msp430_compare_control_t /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__cc_t;


static inline /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__cc_t /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__int2CC(uint16_t x)  ;
#line 84
static inline /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__cc_t /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Control__getControl(void );
#line 136
static inline uint16_t /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Capture__getEvent(void );
#line 160
static inline void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Event__fired(void );






static inline void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Capture__default__captured(uint16_t n);

static inline void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Compare__default__fired(void );

static inline void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Timer__overflow(void );
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Capture__captured(uint16_t time);
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Compare__fired(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
typedef msp430_compare_control_t /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__cc_t;


static inline /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__cc_t /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__int2CC(uint16_t x)  ;
#line 84
static inline /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__cc_t /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Control__getControl(void );
#line 136
static inline uint16_t /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Capture__getEvent(void );
#line 160
static inline void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Event__fired(void );






static inline void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Capture__default__captured(uint16_t n);

static inline void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Compare__default__fired(void );

static inline void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Timer__overflow(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void Msp430TimerCommonP__VectorTimerB1__fired(void );
#line 39
static void Msp430TimerCommonP__VectorTimerA0__fired(void );
#line 39
static void Msp430TimerCommonP__VectorTimerA1__fired(void );
#line 39
static void Msp430TimerCommonP__VectorTimerB0__fired(void );
# 11 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/timer/Msp430TimerCommonP.nc"
void sig_TIMERA0_VECTOR(void ) __attribute((wakeup)) __attribute((interrupt(7)))  ;
void sig_TIMERA1_VECTOR(void ) __attribute((wakeup)) __attribute((interrupt(6)))  ;
void sig_TIMERB0_VECTOR(void ) __attribute((wakeup)) __attribute((interrupt(14)))  ;
void sig_TIMERB1_VECTOR(void ) __attribute((wakeup)) __attribute((interrupt(13)))  ;
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Compare__setEvent(uint16_t time);

static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Compare__setEventFromNow(uint16_t delta);
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static uint16_t /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Timer__get(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__fired(void );
# 76 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__enableEvents(void );
#line 56
static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__setControlAsCompare(void );
#line 77
static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__disableEvents(void );
#line 43
static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__clearPendingInterrupt(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline error_t /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Init__init(void );
#line 65
static inline void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__stop(void );




static inline void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Compare__fired(void );










static inline void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__startAt(uint16_t t0, uint16_t dt);
#line 114
static inline void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Timer__overflow(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static uint16_t /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Msp430Timer__get(void );
static bool /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Msp430Timer__isOverflowPending(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__overflow(void );
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430CounterC.nc"
static inline uint16_t /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__get(void );




static inline bool /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__isOverflowPending(void );









static inline void /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Msp430Timer__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__size_type /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__get(void );






static bool /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__isOverflowPending(void );










static void /*CounterMilli32C.Transform*/TransformCounterC__0__Counter__overflow(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
/*CounterMilli32C.Transform*/TransformCounterC__0__upper_count_type /*CounterMilli32C.Transform*/TransformCounterC__0__m_upper;

enum /*CounterMilli32C.Transform*/TransformCounterC__0____nesc_unnamed4317 {

  TransformCounterC__0__LOW_SHIFT_RIGHT = 5, 
  TransformCounterC__0__HIGH_SHIFT_LEFT = 8 * sizeof(/*CounterMilli32C.Transform*/TransformCounterC__0__from_size_type ) - /*CounterMilli32C.Transform*/TransformCounterC__0__LOW_SHIFT_RIGHT, 
  TransformCounterC__0__NUM_UPPER_BITS = 8 * sizeof(/*CounterMilli32C.Transform*/TransformCounterC__0__to_size_type ) - 8 * sizeof(/*CounterMilli32C.Transform*/TransformCounterC__0__from_size_type ) + 5, 



  TransformCounterC__0__OVERFLOW_MASK = /*CounterMilli32C.Transform*/TransformCounterC__0__NUM_UPPER_BITS ? ((/*CounterMilli32C.Transform*/TransformCounterC__0__upper_count_type )2 << (/*CounterMilli32C.Transform*/TransformCounterC__0__NUM_UPPER_BITS - 1)) - 1 : 0
};

static /*CounterMilli32C.Transform*/TransformCounterC__0__to_size_type /*CounterMilli32C.Transform*/TransformCounterC__0__Counter__get(void );
#line 133
static inline void /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__overflow(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__fired(void );
#line 103
static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__startAt(/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__size_type t0, /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__size_type dt);
#line 73
static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__stop(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Counter__size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Counter__get(void );
# 77 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_t0;
/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_dt;

enum /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0____nesc_unnamed4318 {

  TransformAlarmC__0__MAX_DELAY_LOG2 = 8 * sizeof(/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__from_size_type ) - 1 - 5, 
  TransformAlarmC__0__MAX_DELAY = (/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type )1 << /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__MAX_DELAY_LOG2
};

static inline /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__getNow(void );




static inline /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__getAlarm(void );










static inline void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__stop(void );




static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__set_alarm(void );
#line 147
static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__startAt(/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type t0, /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type dt);
#line 162
static inline void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__fired(void );
#line 177
static inline void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Counter__overflow(void );
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
enum /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0____nesc_unnamed4319 {
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
uint8_t arg_0x7f2558216ca0);
#line 153
enum /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0____nesc_unnamed4320 {
#line 153
  VirtualizeTimerImplP__0__updateFromTimer = 1U
};
#line 153
typedef int /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0____nesc_sillytask_updateFromTimer[/*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__updateFromTimer];
#line 72
enum /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0____nesc_unnamed4321 {
  VirtualizeTimerImplP__0__NUM_TIMERS = 2U, 
  VirtualizeTimerImplP__0__END_OF_LIST = 255
};








#line 77
typedef struct /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0____nesc_unnamed4322 {
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
enum CC2420CsmaP____nesc_unnamed4323 {
#line 74
  CC2420CsmaP__startDone_task = 2U
};
#line 74
typedef int CC2420CsmaP____nesc_sillytask_startDone_task[CC2420CsmaP__startDone_task];
enum CC2420CsmaP____nesc_unnamed4324 {
#line 75
  CC2420CsmaP__stopDone_task = 3U
};
#line 75
typedef int CC2420CsmaP____nesc_sillytask_stopDone_task[CC2420CsmaP__stopDone_task];
enum CC2420CsmaP____nesc_unnamed4325 {
#line 76
  CC2420CsmaP__sendDone_task = 4U
};
#line 76
typedef int CC2420CsmaP____nesc_sillytask_sendDone_task[CC2420CsmaP__sendDone_task];
#line 58
enum CC2420CsmaP____nesc_unnamed4326 {
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
enum CC2420ControlP____nesc_unnamed4327 {
#line 125
  CC2420ControlP__sync = 5U
};
#line 125
typedef int CC2420ControlP____nesc_sillytask_sync[CC2420ControlP__sync];
enum CC2420ControlP____nesc_unnamed4328 {
#line 126
  CC2420ControlP__syncDone = 6U
};
#line 126
typedef int CC2420ControlP____nesc_sillytask_syncDone[CC2420ControlP__syncDone];
#line 90
#line 84
typedef enum CC2420ControlP____nesc_unnamed4329 {
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
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Compare__setEvent(uint16_t time);

static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Compare__setEventFromNow(uint16_t delta);
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static uint16_t /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Timer__get(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__fired(void );
# 76 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__enableEvents(void );
#line 56
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__setControlAsCompare(void );
#line 77
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__disableEvents(void );
#line 43
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__clearPendingInterrupt(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline error_t /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Init__init(void );
#line 65
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__stop(void );




static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Compare__fired(void );










static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__startAt(uint16_t t0, uint16_t dt);
#line 114
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Timer__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__size_type /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__get(void );






static bool /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__isOverflowPending(void );










static void /*Counter32khz32C.Transform*/TransformCounterC__1__Counter__overflow(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
/*Counter32khz32C.Transform*/TransformCounterC__1__upper_count_type /*Counter32khz32C.Transform*/TransformCounterC__1__m_upper;

enum /*Counter32khz32C.Transform*/TransformCounterC__1____nesc_unnamed4330 {

  TransformCounterC__1__LOW_SHIFT_RIGHT = 0, 
  TransformCounterC__1__HIGH_SHIFT_LEFT = 8 * sizeof(/*Counter32khz32C.Transform*/TransformCounterC__1__from_size_type ) - /*Counter32khz32C.Transform*/TransformCounterC__1__LOW_SHIFT_RIGHT, 
  TransformCounterC__1__NUM_UPPER_BITS = 8 * sizeof(/*Counter32khz32C.Transform*/TransformCounterC__1__to_size_type ) - 8 * sizeof(/*Counter32khz32C.Transform*/TransformCounterC__1__from_size_type ) + 0, 



  TransformCounterC__1__OVERFLOW_MASK = /*Counter32khz32C.Transform*/TransformCounterC__1__NUM_UPPER_BITS ? ((/*Counter32khz32C.Transform*/TransformCounterC__1__upper_count_type )2 << (/*Counter32khz32C.Transform*/TransformCounterC__1__NUM_UPPER_BITS - 1)) - 1 : 0
};

static /*Counter32khz32C.Transform*/TransformCounterC__1__to_size_type /*Counter32khz32C.Transform*/TransformCounterC__1__Counter__get(void );
#line 133
static inline void /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__overflow(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__fired(void );
#line 103
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__size_type t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__size_type dt);
#line 73
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__stop(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Counter__size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Counter__get(void );
# 77 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_t0;
/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_dt;

enum /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1____nesc_unnamed4331 {

  TransformAlarmC__1__MAX_DELAY_LOG2 = 8 * sizeof(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__from_size_type ) - 1 - 0, 
  TransformAlarmC__1__MAX_DELAY = (/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type )1 << /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__MAX_DELAY_LOG2
};

static inline /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__getNow(void );
#line 102
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__stop(void );




static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__set_alarm(void );
#line 147
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type dt);









static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__start(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type dt);




static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__fired(void );
#line 177
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Counter__overflow(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__HplGeneralIO__makeInput(void );
#line 74
static bool /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__HplGeneralIO__get(void );
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline bool /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__GeneralIO__get(void );
static inline void /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__GeneralIO__makeInput(void );
# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__HplGeneralIO__makeOutput(void );
#line 49
static void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__HplGeneralIO__set(void );




static void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__HplGeneralIO__clr(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__set(void );
static inline void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__clr(void );




static inline void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__makeOutput(void );
# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static bool /*HplCC2420PinsC.FIFOM*/Msp430GpioC__5__HplGeneralIO__get(void );
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline bool /*HplCC2420PinsC.FIFOM*/Msp430GpioC__5__GeneralIO__get(void );
# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static bool /*HplCC2420PinsC.FIFOPM*/Msp430GpioC__6__HplGeneralIO__get(void );
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline bool /*HplCC2420PinsC.FIFOPM*/Msp430GpioC__6__GeneralIO__get(void );
# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__HplGeneralIO__makeOutput(void );
#line 49
static void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__HplGeneralIO__set(void );




static void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__HplGeneralIO__clr(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__GeneralIO__set(void );
static inline void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__GeneralIO__clr(void );




static inline void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__GeneralIO__makeOutput(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__HplGeneralIO__makeInput(void );
#line 74
static bool /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__HplGeneralIO__get(void );
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline bool /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__GeneralIO__get(void );
static inline void /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__GeneralIO__makeInput(void );
# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__HplGeneralIO__makeOutput(void );
#line 49
static void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__HplGeneralIO__set(void );




static void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__HplGeneralIO__clr(void );
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__GeneralIO__set(void );
static inline void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__GeneralIO__clr(void );




static inline void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__GeneralIO__makeOutput(void );
# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430Capture__clearOverflow(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__captured(uint16_t time);
# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__setControlAsCapture(uint8_t cm, uint8_t ccis);

static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__enableEvents(void );
static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__disableEvents(void );
#line 43
static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__clearPendingInterrupt(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__GeneralIO__makeInput(void );
#line 97
static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__GeneralIO__selectIOFunc(void );
#line 91
static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__GeneralIO__selectModuleFunc(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/GpioCaptureC.nc"
static error_t /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__enableCapture(uint8_t mode);
#line 74
static inline error_t /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__captureRisingEdge(void );



static inline error_t /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__captureFallingEdge(void );



static inline void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__disable(void );






static inline void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430Capture__captured(uint16_t time);
# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
static void HplMsp430InterruptP__Port14__fired(void );
#line 85
static void HplMsp430InterruptP__Port26__fired(void );
#line 85
static void HplMsp430InterruptP__Port17__fired(void );
#line 85
static void HplMsp430InterruptP__Port21__fired(void );
#line 85
static void HplMsp430InterruptP__Port12__fired(void );
#line 85
static void HplMsp430InterruptP__Port24__fired(void );
#line 85
static void HplMsp430InterruptP__Port15__fired(void );
#line 85
static void HplMsp430InterruptP__Port27__fired(void );
#line 85
static void HplMsp430InterruptP__Port10__fired(void );
#line 85
static void HplMsp430InterruptP__Port22__fired(void );
#line 85
static void HplMsp430InterruptP__Port13__fired(void );
#line 85
static void HplMsp430InterruptP__Port25__fired(void );
#line 85
static void HplMsp430InterruptP__Port16__fired(void );
#line 85
static void HplMsp430InterruptP__Port20__fired(void );
#line 85
static void HplMsp430InterruptP__Port11__fired(void );
#line 85
static void HplMsp430InterruptP__Port23__fired(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
void sig_PORT1_VECTOR(void ) __attribute((wakeup)) __attribute((interrupt(5)))  ;
#line 107
static inline void HplMsp430InterruptP__Port11__default__fired(void );
static inline void HplMsp430InterruptP__Port12__default__fired(void );
static inline void HplMsp430InterruptP__Port13__default__fired(void );

static inline void HplMsp430InterruptP__Port15__default__fired(void );
static inline void HplMsp430InterruptP__Port16__default__fired(void );
static inline void HplMsp430InterruptP__Port17__default__fired(void );

static inline void HplMsp430InterruptP__Port10__enable(void );



static inline void HplMsp430InterruptP__Port14__enable(void );




static inline void HplMsp430InterruptP__Port10__disable(void );



static inline void HplMsp430InterruptP__Port14__disable(void );




static inline void HplMsp430InterruptP__Port10__clear(void );
static inline void HplMsp430InterruptP__Port11__clear(void );
static inline void HplMsp430InterruptP__Port12__clear(void );
static inline void HplMsp430InterruptP__Port13__clear(void );
static inline void HplMsp430InterruptP__Port14__clear(void );
static inline void HplMsp430InterruptP__Port15__clear(void );
static inline void HplMsp430InterruptP__Port16__clear(void );
static inline void HplMsp430InterruptP__Port17__clear(void );
#line 155
static inline void HplMsp430InterruptP__Port14__edgeRising(void );




static inline void HplMsp430InterruptP__Port10__edgeFalling(void );
#line 227
void sig_PORT2_VECTOR(void ) __attribute((wakeup)) __attribute((interrupt(2)))  ;
#line 240
static inline void HplMsp430InterruptP__Port20__default__fired(void );
static inline void HplMsp430InterruptP__Port21__default__fired(void );
static inline void HplMsp430InterruptP__Port22__default__fired(void );
static inline void HplMsp430InterruptP__Port23__default__fired(void );
static inline void HplMsp430InterruptP__Port24__default__fired(void );
static inline void HplMsp430InterruptP__Port25__default__fired(void );
static inline void HplMsp430InterruptP__Port26__default__fired(void );
static inline void HplMsp430InterruptP__Port27__default__fired(void );
#line 267
static inline void HplMsp430InterruptP__Port20__clear(void );
static inline void HplMsp430InterruptP__Port21__clear(void );
static inline void HplMsp430InterruptP__Port22__clear(void );
static inline void HplMsp430InterruptP__Port23__clear(void );
static inline void HplMsp430InterruptP__Port24__clear(void );
static inline void HplMsp430InterruptP__Port25__clear(void );
static inline void HplMsp430InterruptP__Port26__clear(void );
static inline void HplMsp430InterruptP__Port27__clear(void );
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
static void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__clear(void );
#line 49
static void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__disable(void );
#line 44
static void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__enable(void );
#line 66
static void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__edgeRising(void );
# 68 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
static void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__Interrupt__fired(void );
# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/Msp430InterruptC.nc"
static inline error_t /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__Interrupt__enableRisingEdge(void );
#line 76
static inline error_t /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__Interrupt__disable(void );
#line 93
static inline void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__fired(void );
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__clear(void );
#line 49
static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__disable(void );
#line 67
static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__edgeFalling(void );
#line 44
static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__enable(void );
# 68 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__Interrupt__fired(void );
# 66 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/Msp430InterruptC.nc"
static inline error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__Interrupt__enableFallingEdge(void );









static inline error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__Interrupt__disable(void );
#line 93
static inline void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__fired(void );
# 76 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
static error_t CC2420SpiP__SpiPacket__send(
#line 65
uint8_t * txBuf, 

uint8_t * rxBuf, 








uint16_t len);
# 91 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
static void CC2420SpiP__Fifo__writeDone(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d946e0, 
# 91 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/CC2420Fifo.nc"
uint8_t * data, uint8_t length, error_t error);
#line 71
static void CC2420SpiP__Fifo__readDone(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
uint8_t arg_0x7f2557d946e0, 
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
uint8_t arg_0x7f2557d95360);
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t CC2420SpiP__grant__postTask(void );
# 88 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/spi/CC2420SpiP.nc"
enum CC2420SpiP____nesc_unnamed4332 {
#line 88
  CC2420SpiP__grant = 7U
};
#line 88
typedef int CC2420SpiP____nesc_sillytask_grant[CC2420SpiP__grant];
#line 63
enum CC2420SpiP____nesc_unnamed4333 {
  CC2420SpiP__RESOURCE_COUNT = 5U, 
  CC2420SpiP__NO_HOLDER = 0xFF
};


enum CC2420SpiP____nesc_unnamed4334 {
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

enum StateImplP____nesc_unnamed4335 {
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
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiPacket__sendDone(
# 79 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8bb50, 
# 81 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
uint8_t * txBuf, 
uint8_t * rxBuf, 





uint16_t len, 
error_t error);
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiConfigure.nc"
static const msp430_spi_union_config_t */*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Msp430SpiConfigure__getConfig(
# 82 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c89d40);
# 180 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__enableRxIntr(void );
#line 197
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__clrRxIntr(void );
#line 97
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__resetUsart(bool reset);
#line 177
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__disableRxIntr(void );
#line 220
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__tx(uint8_t data);
#line 168
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__setModeSpi(const msp430_spi_union_config_t *config);
#line 227
static uint8_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__rx(void );
#line 192
static bool /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__isRxIntrPending(void );
#line 158
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__disableSpi(void );
# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__release(
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8a980);
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__immediateRequest(
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8a980);
# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__request(
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8a980);
# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static bool /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__isOwner(
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8a980);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__granted(
# 75 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
uint8_t arg_0x7f2557c8f770);
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone_task__postTask(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
enum /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0____nesc_unnamed4336 {
#line 102
  Msp430SpiNoDmaP__0__signalDone_task = 8U
};
#line 102
typedef int /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0____nesc_sillytask_signalDone_task[/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone_task];
#line 91
enum /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0____nesc_unnamed4337 {
  Msp430SpiNoDmaP__0__SPI_ATOMIC_SIZE = 2
};

uint16_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_len;
uint8_t * /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_tx_buf;
uint8_t * /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_rx_buf;
uint16_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_pos;
uint8_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_client;

static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone(void );


static inline error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__immediateRequest(uint8_t id);



static inline error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__request(uint8_t id);



static inline bool /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__isOwner(uint8_t id);



static inline error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__release(uint8_t id);



static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__ResourceConfigure__configure(uint8_t id);



static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__ResourceConfigure__unconfigure(uint8_t id);





static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__granted(uint8_t id);



static uint8_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiByte__write(uint8_t tx);
#line 172
static inline bool /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__isOwner(uint8_t id);
static inline error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__request(uint8_t id);
static inline error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__immediateRequest(uint8_t id);
static inline error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__release(uint8_t id);
static inline const msp430_spi_union_config_t */*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Msp430SpiConfigure__default__getConfig(uint8_t id);



static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__default__granted(uint8_t id);

static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__continueOp(void );
#line 205
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiPacket__send(uint8_t id, uint8_t *tx_buf, 
uint8_t *rx_buf, 
uint16_t len);
#line 227
static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone_task__runTask(void );



static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartInterrupts__rxDone(uint8_t data);
#line 244
static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone(void );




static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartInterrupts__txDone(void );

static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiPacket__default__sendDone(uint8_t id, uint8_t *tx_buf, uint8_t *rx_buf, uint16_t len, error_t error);
# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void HplMsp430Usart0P__UCLK__selectIOFunc(void );
#line 91
static void HplMsp430Usart0P__UCLK__selectModuleFunc(void );
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
static void HplMsp430Usart0P__Interrupts__rxDone(uint8_t data);
#line 49
static void HplMsp430Usart0P__Interrupts__txDone(void );
# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void HplMsp430Usart0P__URXD__selectIOFunc(void );
#line 97
static void HplMsp430Usart0P__UTXD__selectIOFunc(void );
# 7 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430I2C.nc"
static void HplMsp430Usart0P__HplI2C__clearModeI2C(void );
#line 6
static bool HplMsp430Usart0P__HplI2C__isI2C(void );
# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void HplMsp430Usart0P__SOMI__selectIOFunc(void );
#line 91
static void HplMsp430Usart0P__SOMI__selectModuleFunc(void );
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430I2CInterrupts.nc"
static void HplMsp430Usart0P__I2CInterrupts__fired(void );
# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void HplMsp430Usart0P__SIMO__selectIOFunc(void );
#line 91
static void HplMsp430Usart0P__SIMO__selectModuleFunc(void );
# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
extern volatile uint8_t HplMsp430Usart0P__IE1 __asm ("IE1");
extern volatile uint8_t HplMsp430Usart0P__ME1 __asm ("ME1");
extern volatile uint8_t HplMsp430Usart0P__IFG1 __asm ("IFG1");

extern volatile uint8_t HplMsp430Usart0P__U0TCTL __asm ("U0TCTL");

extern volatile uint8_t HplMsp430Usart0P__U0TXBUF __asm ("U0TXBUF");

void sig_USART0RX_VECTOR(void ) __attribute((wakeup)) __attribute((interrupt(10)))  ;




void sig_USART0TX_VECTOR(void ) __attribute((wakeup)) __attribute((interrupt(9)))  ;
#line 118
static inline void HplMsp430Usart0P__Usart__setUbr(uint16_t control);










static inline void HplMsp430Usart0P__Usart__setUmctl(uint8_t control);







static inline void HplMsp430Usart0P__Usart__resetUsart(bool reset);
#line 193
static inline void HplMsp430Usart0P__Usart__disableUart(void );
#line 224
static inline void HplMsp430Usart0P__Usart__enableSpi(void );








static void HplMsp430Usart0P__Usart__disableSpi(void );








static inline void HplMsp430Usart0P__configSpi(const msp430_spi_union_config_t *config);








static void HplMsp430Usart0P__Usart__setModeSpi(const msp430_spi_union_config_t *config);
#line 313
static inline bool HplMsp430Usart0P__Usart__isRxIntrPending(void );










static inline void HplMsp430Usart0P__Usart__clrRxIntr(void );



static inline void HplMsp430Usart0P__Usart__clrIntr(void );



static inline void HplMsp430Usart0P__Usart__disableRxIntr(void );







static inline void HplMsp430Usart0P__Usart__disableIntr(void );



static inline void HplMsp430Usart0P__Usart__enableRxIntr(void );
#line 365
static inline void HplMsp430Usart0P__Usart__tx(uint8_t data);



static inline uint8_t HplMsp430Usart0P__Usart__rx(void );
# 90 "/home/wtiberti/WSN/tinyos/tos/interfaces/ArbiterInfo.nc"
static bool /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__ArbiterInfo__inUse(void );







static uint8_t /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__ArbiterInfo__userId(void );
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
static void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__rxDone(
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
uint8_t arg_0x7f2557b16cd0, 
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
uint8_t data);
#line 49
static void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__txDone(
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
uint8_t arg_0x7f2557b16cd0);
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430I2CInterrupts.nc"
static void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__I2CInterrupts__fired(
# 40 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
uint8_t arg_0x7f2557b15b80);








static inline void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__RawInterrupts__txDone(void );




static inline void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__RawInterrupts__rxDone(uint8_t data);




static inline void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__RawI2CInterrupts__fired(void );




static inline void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__default__txDone(uint8_t id);
static inline void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__default__rxDone(uint8_t id, uint8_t data);
static inline void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__I2CInterrupts__default__fired(uint8_t id);
# 49 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
enum /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1____nesc_unnamed4338 {
#line 49
  FcfsResourceQueueC__1__NO_ENTRY = 0xFF
};
uint8_t /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__resQ[1U];
uint8_t /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qHead = /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__NO_ENTRY;
uint8_t /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qTail = /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__NO_ENTRY;

static inline error_t /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__Init__init(void );




static inline bool /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEmpty(void );



static inline bool /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEnqueued(resource_client_id_t id);



static resource_client_id_t /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__dequeue(void );
#line 82
static inline error_t /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__enqueue(resource_client_id_t id);
# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__requested(
# 99 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad49d0);
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__immediateRequested(
# 99 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad49d0);
# 65 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__unconfigure(
# 105 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad06b0);
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__configure(
# 105 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad06b0);
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
static error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Queue__enqueue(resource_client_id_t id);
#line 53
static bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Queue__isEmpty(void );
#line 70
static resource_client_id_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Queue__dequeue(void );
# 71 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwner.nc"
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__requested(void );
#line 44
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__granted(void );
#line 79
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__immediateRequested(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__granted(
# 98 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad56a0);
# 9 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwnerInfo.nc"
static bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwnerInfo__inUse(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__grantedTask__postTask(void );
# 155 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
enum /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0____nesc_unnamed4339 {
#line 155
  ArbiterP__0__grantedTask = 9U
};
#line 155
typedef int /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0____nesc_sillytask_grantedTask[/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__grantedTask];
#line 145
#line 143
typedef enum /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0____nesc_unnamed4340 {
#line 143
  ArbiterP__0__RES_DEF_OWNED = 0, ArbiterP__0__RES_PREGRANT, ArbiterP__0__RES_GRANTING, 
  ArbiterP__0__RES_IMM_GRANTING, ArbiterP__0__RES_BUSY
} /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__arb_state_t;

enum /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0____nesc_unnamed4341 {
#line 147
  ArbiterP__0__default_owner_id = 1U
};
#line 148
enum /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0____nesc_unnamed4342 {
#line 148
  ArbiterP__0__NO_RES = 0xFF
};
#line 149
enum /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0____nesc_unnamed4343 {
#line 149
  ArbiterP__0__arbiter_id = 0U
};
/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__arb_state_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state;
uint8_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__default_owner_id;
uint8_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__reqResId = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__NO_RES;



static inline error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__request(uint8_t id);
#line 222
static inline error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__immediateRequest(uint8_t id);
#line 249
static inline error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__release(uint8_t id);
#line 283
static error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__release(void );
#line 307
static bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ArbiterInfo__inUse(void );
#line 331
static inline uint8_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ArbiterInfo__userId(void );






static inline bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__isOwner(uint8_t id);







static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__grantedTask__runTask(void );
#line 363
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__default__granted(uint8_t id);
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__default__requested(uint8_t id);
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__default__immediateRequested(uint8_t id);
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__default__granted(void );
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__default__configure(uint8_t id);
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__default__unconfigure(uint8_t id);

static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__default__requested(void );



static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__default__immediateRequested(void );



static inline bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwnerInfo__default__inUse(void );
# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
static void HplMsp430I2C0P__HplUsart__resetUsart(bool reset);
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430I2C0P.nc"
extern volatile uint8_t HplMsp430I2C0P__U0CTL __asm ("U0CTL");





static inline bool HplMsp430I2C0P__HplI2C__isI2C(void );



static inline void HplMsp430I2C0P__HplI2C__clearModeI2C(void );
# 63 "/home/wtiberti/WSN/tinyos/tos/system/ActiveMessageAddressC.nc"
am_addr_t ActiveMessageAddressC__addr = TOS_AM_ADDRESS;


am_group_t ActiveMessageAddressC__group = TOS_AM_GROUP;






static inline am_addr_t ActiveMessageAddressC__ActiveMessageAddress__amAddress(void );
#line 94
static inline am_group_t ActiveMessageAddressC__ActiveMessageAddress__amGroup(void );
#line 120
static am_addr_t ActiveMessageAddressC__amAddress(void );
# 13 "/home/wtiberti/WSN/tinyos/tos/chips/ds2411/ReadId48.nc"
static error_t LocalIeeeEui64P__ReadId48__read(uint8_t *id);
# 13 "/home/wtiberti/WSN/tinyos/tos/chips/ds2411/LocalIeeeEui64P.nc"
ieee_eui64_t LocalIeeeEui64P__eui = { { 0x00 } };

bool LocalIeeeEui64P__have_id = FALSE;

static ieee_eui64_t LocalIeeeEui64P__LocalIeeeEui64__getId(void );
# 10 "/home/wtiberti/WSN/tinyos/tos/lib/onewire/OneWireReadWrite.nc"
static error_t Ds2411P__OneWire__read(uint8_t cmd, uint8_t *buf, uint8_t len);
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t Ds2411P__PowerControl__start(void );









static error_t Ds2411P__PowerControl__stop(void );
# 19 "/home/wtiberti/WSN/tinyos/tos/chips/ds2411/Ds2411P.nc"
bool Ds2411P__haveId = FALSE;
ds2411_serial_t Ds2411P__ds2411id;



static inline bool Ds2411P__ds2411_check_crc(const ds2411_serial_t *id);
#line 41
static inline error_t Ds2411P__readId(void );
#line 62
static inline error_t Ds2411P__ReadId48__read(uint8_t *id);
# 66 "/home/wtiberti/WSN/tinyos/tos/lib/timer/BusyWait.nc"
static void OneWireMasterP__BusyWait__wait(OneWireMasterP__BusyWait__size_type dt);
# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
static void OneWireMasterP__Pin__makeInput(void );
#line 43
static bool OneWireMasterP__Pin__get(void );


static void OneWireMasterP__Pin__makeOutput(void );
#line 41
static void OneWireMasterP__Pin__clr(void );
# 27 "/home/wtiberti/WSN/tinyos/tos/lib/onewire/OneWireMasterP.nc"
#line 20
typedef enum OneWireMasterP____nesc_unnamed4344 {
  OneWireMasterP__DELAY_5US = 5, 
  OneWireMasterP__RESET_LOW_TIME = 560, 
  OneWireMasterP__DELAY_60US = 60, 
  OneWireMasterP__PRESENCE_DETECT_LOW_TIME = 240, 
  OneWireMasterP__PRESENCE_RESET_HIGH_TIME = 480, 
  OneWireMasterP__SLOT_TIME = 65
} OneWireMasterP__onewiretimes_t;






static inline bool OneWireMasterP__reset(void );
#line 52
static inline void OneWireMasterP__writeOne(void );






static inline void OneWireMasterP__writeZero(void );






static inline bool OneWireMasterP__readBit(void );










static inline void OneWireMasterP__writeByte(uint8_t c);
#line 89
static inline uint8_t OneWireMasterP__readByte(void );










static inline error_t OneWireMasterP__OneWire__read(uint8_t cmd, uint8_t *buf, uint8_t len);
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__size_type /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__get(void );
# 59 "/home/wtiberti/WSN/tinyos/tos/lib/timer/BusyWaitCounterC.nc"
enum /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0____nesc_unnamed4345 {

  BusyWaitCounterC__0__HALF_MAX_SIZE_TYPE = (/*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__size_type )1 << (8 * sizeof(/*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__size_type ) - 1)
};

static void /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__BusyWait__wait(/*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__size_type dt);
#line 85
static inline void /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__overflow(void );
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static uint16_t /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Msp430Timer__get(void );
# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static void /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Counter__overflow(void );
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430CounterC.nc"
static inline uint16_t /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Counter__get(void );
#line 64
static inline void /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Msp430Timer__overflow(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void /*HplDs2411C.MspGpio*/Msp430GpioC__10__HplGeneralIO__makeInput(void );





static void /*HplDs2411C.MspGpio*/Msp430GpioC__10__HplGeneralIO__makeOutput(void );
#line 74
static bool /*HplDs2411C.MspGpio*/Msp430GpioC__10__HplGeneralIO__get(void );
#line 54
static void /*HplDs2411C.MspGpio*/Msp430GpioC__10__HplGeneralIO__clr(void );
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__clr(void );

static inline bool /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__get(void );
static inline void /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__makeInput(void );

static inline void /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__makeOutput(void );
# 19 "/home/wtiberti/WSN/tinyos/tos/chips/ds2411/Ds2411PowerControlC.nc"
static inline error_t Ds2411PowerControlC__StdControl__start(void );



static inline error_t Ds2411PowerControlC__StdControl__stop(void );
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
typedef enum CC2420TransmitP____nesc_unnamed4346 {
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





enum CC2420TransmitP____nesc_unnamed4347 {
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
enum CC2420ReceiveP____nesc_unnamed4348 {
#line 148
  CC2420ReceiveP__receiveDone_task = 10U
};
#line 148
typedef int CC2420ReceiveP____nesc_sillytask_receiveDone_task[CC2420ReceiveP__receiveDone_task];
#line 89
#line 81
typedef enum CC2420ReceiveP____nesc_unnamed4349 {
  CC2420ReceiveP__S_STOPPED, 
  CC2420ReceiveP__S_STARTED, 
  CC2420ReceiveP__S_RX_LENGTH, 
  CC2420ReceiveP__S_RX_DEC, 
  CC2420ReceiveP__S_RX_DEC_WAIT, 
  CC2420ReceiveP__S_RX_FCF, 
  CC2420ReceiveP__S_RX_PAYLOAD
} CC2420ReceiveP__cc2420_receive_state_t;

enum CC2420ReceiveP____nesc_unnamed4350 {
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

enum UniqueSendP____nesc_unnamed4351 {
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
struct UniqueReceiveP____nesc_unnamed4352 {
  uint16_t source;
  uint8_t dsn;
} UniqueReceiveP__receivedMessages[4];

uint8_t UniqueReceiveP__writeIndex = 0;


uint8_t UniqueReceiveP__recycleSourceElement;

enum UniqueReceiveP____nesc_unnamed4353 {
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
uint8_t arg_0x7f255758f600);
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
enum CC2420TinyosNetworkP____nesc_unnamed4354 {
#line 184
  CC2420TinyosNetworkP__grantTask = 11U
};
#line 184
typedef int CC2420TinyosNetworkP____nesc_sillytask_grantTask[CC2420TinyosNetworkP__grantTask];
#line 68
enum CC2420TinyosNetworkP____nesc_unnamed4355 {
  CC2420TinyosNetworkP__OWNER_NONE = 0xff, 
  CC2420TinyosNetworkP__TINYOS_N_NETWORKS = 1U
};




#line 73
enum CC2420TinyosNetworkP____nesc_unnamed4356 {
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
enum /*CC2420TinyosNetworkC.FcfsResourceQueueC*/FcfsResourceQueueC__0____nesc_unnamed4357 {
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
am_id_t arg_0x7f25574f8700, 
# 95 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
message_t * msg);
#line 81
static void CC2420ActiveMessageP__RadioBackoff__requestInitialBackoff(
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f25574f8700, 
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
message_t * msg);






static void CC2420ActiveMessageP__RadioBackoff__requestCongestionBackoff(
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f25574f8700, 
# 88 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/interfaces/RadioBackoff.nc"
message_t * msg);
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/SendNotifier.nc"
static void CC2420ActiveMessageP__SendNotifier__aboutToSend(
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f25574f9b30, 
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/SendNotifier.nc"
am_addr_t dest, 
#line 57
message_t * msg);
# 110 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
static void CC2420ActiveMessageP__AMSend__sendDone(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f2557501cf0, 
# 103 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
message_t * msg, 






error_t error);
# 78 "/home/wtiberti/WSN/tinyos/tos/interfaces/Receive.nc"
static 
#line 74
message_t * 



CC2420ActiveMessageP__Snoop__receive(
# 50 "/home/wtiberti/WSN/tinyos/tos/chips/cc2420/CC2420ActiveMessageP.nc"
am_id_t arg_0x7f25574fcc40, 
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
am_id_t arg_0x7f25574fc060, 
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
am_id_t arg_0x7f2557435510, 
# 80 "/home/wtiberti/WSN/tinyos/tos/interfaces/AMSend.nc"
am_addr_t addr, 
#line 71
message_t * msg, 








uint8_t len);
# 100 "/home/wtiberti/WSN/tinyos/tos/interfaces/Send.nc"
static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__sendDone(
# 47 "/home/wtiberti/WSN/tinyos/tos/system/AMQueueImplP.nc"
uint8_t arg_0x7f2557438960, 
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
enum /*AMQueueP.AMQueueImplP*/AMQueueImplP__0____nesc_unnamed4358 {
#line 140
  AMQueueImplP__0__CancelTask = 12U
};
#line 140
typedef int /*AMQueueP.AMQueueImplP*/AMQueueImplP__0____nesc_sillytask_CancelTask[/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__CancelTask];
#line 184
enum /*AMQueueP.AMQueueImplP*/AMQueueImplP__0____nesc_unnamed4359 {
#line 184
  AMQueueImplP__0__errorTask = 13U
};
#line 184
typedef int /*AMQueueP.AMQueueImplP*/AMQueueImplP__0____nesc_sillytask_errorTask[/*AMQueueP.AMQueueImplP*/AMQueueImplP__0__errorTask];
#line 60
#line 58
typedef struct /*AMQueueP.AMQueueImplP*/AMQueueImplP__0____nesc_unnamed4360 {
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
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static Msp430HybridAlarmCounterP__CounterMicro__size_type Msp430HybridAlarmCounterP__CounterMicro__get(void );
#line 82
static void Msp430HybridAlarmCounterP__Counter2ghz__overflow(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void Msp430HybridAlarmCounterP__Alarm2ghz__fired(void );
#line 103
static void Msp430HybridAlarmCounterP__AlarmMicro__startAt(Msp430HybridAlarmCounterP__AlarmMicro__size_type t0, Msp430HybridAlarmCounterP__AlarmMicro__size_type dt);
#line 88
static bool Msp430HybridAlarmCounterP__AlarmMicro__isRunning(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static Msp430HybridAlarmCounterP__Counter32khz__size_type Msp430HybridAlarmCounterP__Counter32khz__get(void );






static bool Msp430HybridAlarmCounterP__Counter32khz__isOverflowPending(void );
# 50 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430HybridAlarmCounterP.nc"
uint32_t Msp430HybridAlarmCounterP__fireTime;


static __inline uint16_t Msp430HybridAlarmCounterP__now32khz(void );



static __inline uint16_t Msp430HybridAlarmCounterP__nowMicro(void );




static __inline void Msp430HybridAlarmCounterP__now(uint16_t *t32khz, uint16_t *tMicro, uint32_t *t2ghz);
#line 86
static __inline uint32_t Msp430HybridAlarmCounterP__now2ghz(void );
#line 101
static inline uint32_t Msp430HybridAlarmCounterP__Counter2ghz__get(void );








static inline bool Msp430HybridAlarmCounterP__Counter2ghz__isOverflowPending(void );
#line 124
static inline void Msp430HybridAlarmCounterP__Counter32khz__overflow(void );



static inline void Msp430HybridAlarmCounterP__CounterMicro__overflow(void );
#line 163
static inline void Msp430HybridAlarmCounterP__Alarm32khz__fired(void );
#line 176
static inline void Msp430HybridAlarmCounterP__AlarmMicro__fired(void );
#line 191
static inline void Msp430HybridAlarmCounterP__Alarm2ghz__default__fired(void );
#line 260
static inline mcu_power_t Msp430HybridAlarmCounterP__McuPowerOverride__lowestState(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Alarm__fired(void );
# 77 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static void /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Msp430TimerControl__disableEvents(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Msp430Compare__fired(void );
#line 114
static inline void /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Msp430Timer__overflow(void );
# 42 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Compare__setEvent(uint16_t time);

static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Compare__setEventFromNow(uint16_t delta);
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
static uint16_t /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Timer__get(void );
# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__fired(void );
# 76 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430TimerControl__enableEvents(void );

static bool /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430TimerControl__areEventsEnabled(void );
#line 77
static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430TimerControl__disableEvents(void );
#line 43
static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430TimerControl__clearPendingInterrupt(void );
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Compare__fired(void );





static inline bool /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__isRunning(void );




static inline void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__startAt(uint16_t t0, uint16_t dt);
#line 114
static inline void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Timer__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__size_type /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__get(void );






static bool /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__isOverflowPending(void );










static void /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__Counter__overflow(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
/*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__upper_count_type /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__m_upper;

enum /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2____nesc_unnamed4361 {

  TransformCounterC__2__LOW_SHIFT_RIGHT = 11, 
  TransformCounterC__2__HIGH_SHIFT_LEFT = 8 * sizeof(/*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__from_size_type ) - /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__LOW_SHIFT_RIGHT, 
  TransformCounterC__2__NUM_UPPER_BITS = 8 * sizeof(/*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__to_size_type ) - 8 * sizeof(/*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__from_size_type ) + 11, 



  TransformCounterC__2__OVERFLOW_MASK = /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__NUM_UPPER_BITS ? ((/*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__upper_count_type )2 << (/*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__NUM_UPPER_BITS - 1)) - 1 : 0
};

static inline /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__to_size_type /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__Counter__get(void );
#line 133
static inline void /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__overflow(void );
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
static /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__size_type /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__get(void );
# 53 "/home/wtiberti/WSN/tinyos/tos/lib/timer/CounterToLocalTimeC.nc"
static inline uint32_t /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__LocalTime__get(void );




static inline void /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__overflow(void );
# 50 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartByte.nc"
static error_t SerialPrintfP__UartByte__send(uint8_t byte);
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
static error_t SerialPrintfP__UartControl__start(void );
# 50 "/home/wtiberti/WSN/tinyos/tos/lib/printf/SerialPrintfP.nc"
static inline error_t SerialPrintfP__Init__init(void );



static inline error_t SerialPrintfP__StdControl__start(void );









int printfflush(void )   ;




static inline int SerialPrintfP__Putchar__putchar(int c);
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartConfigure.nc"
static const msp430_uart_union_config_t */*Msp430Uart1P.UartP*/Msp430UartP__0__Msp430UartConfigure__getConfig(
# 52 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f2557262020);
# 181 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__enableTxIntr(void );
#line 178
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__disableTxIntr(void );



static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__enableIntr(void );




static bool /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__isTxIntrPending(void );
#line 220
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__tx(uint8_t data);
#line 174
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__setModeUart(const msp430_uart_union_config_t *config);
#line 202
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__clrTxIntr(void );
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__receivedByte(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f25572674c0, 
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
uint8_t byte);
#line 99
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__receiveDone(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f25572674c0, 
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
uint8_t * buf, 



uint16_t len, error_t error);
#line 57
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__sendDone(
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f25572674c0, 
# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
uint8_t * buf, 



uint16_t len, error_t error);
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__immediateRequest(
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f2557265ca0);
# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static bool /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__isOwner(
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f2557265ca0);
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Resource__granted(
# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
uint8_t arg_0x7f255726a410);
#line 62
uint16_t /*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_len;
#line 62
uint16_t /*Msp430Uart1P.UartP*/Msp430UartP__0__m_rx_len;
uint8_t * /*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_buf;
#line 63
uint8_t * /*Msp430Uart1P.UartP*/Msp430UartP__0__m_rx_buf;
uint16_t /*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_pos;
#line 64
uint16_t /*Msp430Uart1P.UartP*/Msp430UartP__0__m_rx_pos;
uint8_t /*Msp430Uart1P.UartP*/Msp430UartP__0__m_byte_time;
uint8_t /*Msp430Uart1P.UartP*/Msp430UartP__0__current_owner;

static inline error_t /*Msp430Uart1P.UartP*/Msp430UartP__0__Resource__immediateRequest(uint8_t id);
#line 88
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__ResourceConfigure__configure(uint8_t id);
#line 103
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__granted(uint8_t id);
#line 136
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartInterrupts__rxDone(uint8_t id, uint8_t data);
#line 164
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartInterrupts__txDone(uint8_t id);
#line 180
static inline error_t /*Msp430Uart1P.UartP*/Msp430UartP__0__UartByte__send(uint8_t id, uint8_t data);
#line 230
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__Counter__overflow(void );

static inline bool /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__default__isOwner(uint8_t id);

static inline error_t /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__default__immediateRequest(uint8_t id);

static inline const msp430_uart_union_config_t */*Msp430Uart1P.UartP*/Msp430UartP__0__Msp430UartConfigure__default__getConfig(uint8_t id);



static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__Resource__default__granted(uint8_t id);

static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__default__sendDone(uint8_t id, uint8_t *buf, uint16_t len, error_t error);
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__default__receivedByte(uint8_t id, uint8_t byte);
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__default__receiveDone(uint8_t id, uint8_t *buf, uint16_t len, error_t error);
# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void HplMsp430Usart1P__UCLK__selectIOFunc(void );
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
static void HplMsp430Usart1P__Interrupts__rxDone(uint8_t data);
#line 49
static void HplMsp430Usart1P__Interrupts__txDone(void );
# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
static void HplMsp430Usart1P__URXD__selectIOFunc(void );
#line 91
static void HplMsp430Usart1P__URXD__selectModuleFunc(void );





static void HplMsp430Usart1P__UTXD__selectIOFunc(void );
#line 91
static void HplMsp430Usart1P__UTXD__selectModuleFunc(void );





static void HplMsp430Usart1P__SOMI__selectIOFunc(void );
#line 97
static void HplMsp430Usart1P__SIMO__selectIOFunc(void );
# 73 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
extern volatile uint8_t HplMsp430Usart1P__IE2 __asm ("IE2");
extern volatile uint8_t HplMsp430Usart1P__ME2 __asm ("ME2");
extern volatile uint8_t HplMsp430Usart1P__IFG2 __asm ("IFG2");
extern volatile uint8_t HplMsp430Usart1P__U1TCTL __asm ("U1TCTL");
extern volatile uint8_t HplMsp430Usart1P__U1RCTL __asm ("U1RCTL");
extern volatile uint8_t HplMsp430Usart1P__U1TXBUF __asm ("U1TXBUF");



void sig_USART1RX_VECTOR(void ) __attribute((wakeup)) __attribute((interrupt(4)))  ;




void sig_USART1TX_VECTOR(void ) __attribute((wakeup)) __attribute((interrupt(3)))  ;



static inline error_t HplMsp430Usart1P__AsyncStdControl__start(void );
#line 126
static inline void HplMsp430Usart1P__Usart__setUbr(uint16_t control);










static inline void HplMsp430Usart1P__Usart__setUmctl(uint8_t control);







static inline void HplMsp430Usart1P__Usart__resetUsart(bool reset);
#line 189
static inline void HplMsp430Usart1P__Usart__enableUart(void );







static inline void HplMsp430Usart1P__Usart__disableUart(void );








static inline void HplMsp430Usart1P__Usart__enableUartTx(void );




static inline void HplMsp430Usart1P__Usart__disableUartTx(void );





static inline void HplMsp430Usart1P__Usart__enableUartRx(void );




static inline void HplMsp430Usart1P__Usart__disableUartRx(void );
#line 237
static inline void HplMsp430Usart1P__Usart__disableSpi(void );
#line 269
static inline void HplMsp430Usart1P__configUart(const msp430_uart_union_config_t *config);









static inline void HplMsp430Usart1P__Usart__setModeUart(const msp430_uart_union_config_t *config);
#line 302
static inline bool HplMsp430Usart1P__Usart__isTxIntrPending(void );
#line 323
static inline void HplMsp430Usart1P__Usart__clrTxIntr(void );







static inline void HplMsp430Usart1P__Usart__clrIntr(void );







static inline void HplMsp430Usart1P__Usart__disableTxIntr(void );



static inline void HplMsp430Usart1P__Usart__disableIntr(void );










static inline void HplMsp430Usart1P__Usart__enableTxIntr(void );






static inline void HplMsp430Usart1P__Usart__enableIntr(void );






static inline void HplMsp430Usart1P__Usart__tx(uint8_t data);
# 90 "/home/wtiberti/WSN/tinyos/tos/interfaces/ArbiterInfo.nc"
static bool /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__ArbiterInfo__inUse(void );







static uint8_t /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__ArbiterInfo__userId(void );
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
static void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__rxDone(
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
uint8_t arg_0x7f2557b16cd0, 
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
uint8_t data);
#line 49
static void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__txDone(
# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
uint8_t arg_0x7f2557b16cd0);









static inline void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__RawInterrupts__txDone(void );




static inline void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__RawInterrupts__rxDone(uint8_t data);









static inline void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__default__txDone(uint8_t id);
static inline void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__default__rxDone(uint8_t id, uint8_t data);
# 49 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
enum /*Msp430UsartShare1P.ArbiterC.Queue*/FcfsResourceQueueC__2____nesc_unnamed4362 {
#line 49
  FcfsResourceQueueC__2__NO_ENTRY = 0xFF
};
uint8_t /*Msp430UsartShare1P.ArbiterC.Queue*/FcfsResourceQueueC__2__resQ[1U];



static inline error_t /*Msp430UsartShare1P.ArbiterC.Queue*/FcfsResourceQueueC__2__Init__init(void );
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
static void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceRequested__immediateRequested(
# 99 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad49d0);
# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
static void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceConfigure__configure(
# 105 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad06b0);
# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwner.nc"
static void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwner__immediateRequested(void );
# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__granted(
# 98 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
uint8_t arg_0x7f2557ad56a0);
# 9 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwnerInfo.nc"
static bool /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwnerInfo__inUse(void );
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
static error_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__grantedTask__postTask(void );
# 155 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
enum /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1____nesc_unnamed4363 {
#line 155
  ArbiterP__1__grantedTask = 14U
};
#line 155
typedef int /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1____nesc_sillytask_grantedTask[/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__grantedTask];
#line 145
#line 143
typedef enum /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1____nesc_unnamed4364 {
#line 143
  ArbiterP__1__RES_DEF_OWNED = 0, ArbiterP__1__RES_PREGRANT, ArbiterP__1__RES_GRANTING, 
  ArbiterP__1__RES_IMM_GRANTING, ArbiterP__1__RES_BUSY
} /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__arb_state_t;

enum /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1____nesc_unnamed4365 {
#line 147
  ArbiterP__1__default_owner_id = 1U
};
#line 148
enum /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1____nesc_unnamed4366 {
#line 148
  ArbiterP__1__NO_RES = 0xFF
};
#line 149
enum /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1____nesc_unnamed4367 {
#line 149
  ArbiterP__1__arbiter_id = 1U
};
/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__arb_state_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__state;
uint8_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__resId = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__default_owner_id;
uint8_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__reqResId = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__NO_RES;
#line 222
static inline error_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__immediateRequest(uint8_t id);
#line 283
static inline error_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwner__release(void );
#line 307
static bool /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ArbiterInfo__inUse(void );
#line 331
static inline uint8_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ArbiterInfo__userId(void );






static inline bool /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__isOwner(uint8_t id);







static inline void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__grantedTask__runTask(void );
#line 363
static inline void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__default__granted(uint8_t id);

static inline void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceRequested__default__immediateRequested(uint8_t id);

static inline void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceConfigure__default__configure(uint8_t id);










static inline bool /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwnerInfo__default__inUse(void );
# 54 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwner.nc"
static error_t /*Msp430UsartShare1P.PowerManagerC.PowerManager*/AsyncPowerManagerP__0__ResourceDefaultOwner__release(void );
# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/AsyncStdControl.nc"
static error_t /*Msp430UsartShare1P.PowerManagerC.PowerManager*/AsyncPowerManagerP__0__AsyncStdControl__start(void );
# 74 "/home/wtiberti/WSN/tinyos/tos/lib/power/AsyncPowerManagerP.nc"
static inline void /*Msp430UsartShare1P.PowerManagerC.PowerManager*/AsyncPowerManagerP__0__ResourceDefaultOwner__immediateRequested(void );
# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
static error_t TelosSerialP__Resource__immediateRequest(void );
# 8 "/home/wtiberti/WSN/tinyos/tos/platforms/telosa/TelosSerialP.nc"
const msp430_uart_union_config_t TelosSerialP__msp430_uart_telos_config = { { 
.ubr = UBR_1MIHZ_115200, 
.umctl = UMCTL_1MIHZ_115200, 
.ssel = 0x02, .pena = 0, .pev = 0, .spb = 0, .clen = 1, .listen = 0, .mm = 0, 
.ckpl = 0, .urxse = 0, .urxeie = 1, .urxwie = 0, .utxe = 1, .urxe = 1 } };


static inline error_t TelosSerialP__StdControl__start(void );








static inline void TelosSerialP__Resource__granted(void );

static inline const msp430_uart_union_config_t *TelosSerialP__Msp430UartConfigure__getConfig(void );
# 49 "/home/wtiberti/WSN/tinyos/tos/lib/printf/Putchar.nc"
static int PutcharP__Putchar__putchar(int c);
# 98 "/home/wtiberti/WSN/tinyos/tos/lib/printf/PutcharP.nc"
static inline error_t PutcharP__Init__init(void );








int putchar(int c) __attribute((noinline))   ;
# 655 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/msp430hardware.h"
__inline  __attribute((always_inline))  __nesc_atomic_t __nesc_atomic_start(void )
#line 655
{
  __nesc_atomic_t result = ({
#line 656
    unsigned int __x;

#line 656
     __asm volatile ("mov SR, %0" : "=r"((unsigned int )__x));__x;
  }
  )
#line 656
   & 0x0008;


   __asm volatile ("nop");

   __asm volatile ("dint { nop");



   __asm volatile ("nop");


   __asm volatile ("" :  :  : "memory");
  return result;
}

__inline  __attribute((always_inline))  void __nesc_atomic_end(__nesc_atomic_t reenable_interrupts)
#line 672
{
   __asm volatile ("" :  :  : "memory");
  if (reenable_interrupts) {

     __asm volatile ("nop");
    }
   __asm volatile ("eint { nop");}

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
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__HplGeneralIO__set(void ){
#line 49
  /*HplMsp430GeneralIOC.P56*/HplMsp430GeneralIOP__38__IO__set();
#line 49
}
#line 49
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__GeneralIO__set(void )
#line 48
{
#line 48
  /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__HplGeneralIO__set();
}

# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led2__set(void ){
#line 40
  /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__GeneralIO__set();
#line 40
}
#line 40
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__HplGeneralIO__set(void ){
#line 49
  /*HplMsp430GeneralIOC.P55*/HplMsp430GeneralIOP__37__IO__set();
#line 49
}
#line 49
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__GeneralIO__set(void )
#line 48
{
#line 48
  /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__HplGeneralIO__set();
}

# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led1__set(void ){
#line 40
  /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__GeneralIO__set();
#line 40
}
#line 40
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__HplGeneralIO__set(void ){
#line 49
  /*HplMsp430GeneralIOC.P54*/HplMsp430GeneralIOP__36__IO__set();
#line 49
}
#line 49
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__GeneralIO__set(void )
#line 48
{
#line 48
  /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__HplGeneralIO__set();
}

# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led0__set(void ){
#line 40
  /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__GeneralIO__set();
#line 40
}
#line 40
# 102 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P56*/HplMsp430GeneralIOP__38__IO__makeOutput(void )
#line 102
{
  /* atomic removed: atomic calls only */
#line 102
  * (volatile uint8_t * )50U |= 0x01 << 6;
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__HplGeneralIO__makeOutput(void ){
#line 85
  /*HplMsp430GeneralIOC.P56*/HplMsp430GeneralIOP__38__IO__makeOutput();
#line 85
}
#line 85
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__GeneralIO__makeOutput(void )
#line 54
{
#line 54
  /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__HplGeneralIO__makeOutput();
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led2__makeOutput(void ){
#line 46
  /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__GeneralIO__makeOutput();
#line 46
}
#line 46
# 102 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P55*/HplMsp430GeneralIOP__37__IO__makeOutput(void )
#line 102
{
  /* atomic removed: atomic calls only */
#line 102
  * (volatile uint8_t * )50U |= 0x01 << 5;
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__HplGeneralIO__makeOutput(void ){
#line 85
  /*HplMsp430GeneralIOC.P55*/HplMsp430GeneralIOP__37__IO__makeOutput();
#line 85
}
#line 85
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__GeneralIO__makeOutput(void )
#line 54
{
#line 54
  /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__HplGeneralIO__makeOutput();
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led1__makeOutput(void ){
#line 46
  /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__GeneralIO__makeOutput();
#line 46
}
#line 46
# 102 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P54*/HplMsp430GeneralIOP__36__IO__makeOutput(void )
#line 102
{
  /* atomic removed: atomic calls only */
#line 102
  * (volatile uint8_t * )50U |= 0x01 << 4;
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__HplGeneralIO__makeOutput(void ){
#line 85
  /*HplMsp430GeneralIOC.P54*/HplMsp430GeneralIOP__36__IO__makeOutput();
#line 85
}
#line 85
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__GeneralIO__makeOutput(void )
#line 54
{
#line 54
  /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__HplGeneralIO__makeOutput();
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led0__makeOutput(void ){
#line 46
  /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__GeneralIO__makeOutput();
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
inline static error_t PlatformP__LedsInit__init(void ){
#line 62
  enum __nesc_unnamed4242 __nesc_result;
#line 62

#line 62
  __nesc_result = LedsP__Init__init();
#line 62

#line 62
  return __nesc_result;
#line 62
}
#line 62
# 36 "/home/wtiberti/WSN/tinyos/tos/platforms/telosb/hardware.h"
static inline  void TOSH_SET_SIMO0_PIN()
#line 36
{
#line 36
  extern volatile uint8_t r __asm ("P3OUT");

#line 36
  r |= 1 << 1;
}

#line 37
static inline  void TOSH_SET_UCLK0_PIN()
#line 37
{
#line 37
  extern volatile uint8_t r __asm ("P3OUT");

#line 37
  r |= 1 << 3;
}

#line 88
static inline  void TOSH_SET_FLASH_CS_PIN()
#line 88
{
#line 88
  extern volatile uint8_t r __asm ("P4OUT");

#line 88
  r |= 1 << 4;
}

#line 37
static inline  void TOSH_CLR_UCLK0_PIN()
#line 37
{
#line 37
  extern volatile uint8_t r __asm ("P3OUT");

#line 37
  r &= ~(1 << 3);
}

#line 88
static inline  void TOSH_CLR_FLASH_CS_PIN()
#line 88
{
#line 88
  extern volatile uint8_t r __asm ("P4OUT");

#line 88
  r &= ~(1 << 4);
}

# 11 "/home/wtiberti/WSN/tinyos/tos/platforms/telosb/MotePlatformC.nc"
static __inline void MotePlatformC__TOSH_wait(void )
#line 11
{
   __asm volatile ("nop"); __asm volatile ("nop");}

# 89 "/home/wtiberti/WSN/tinyos/tos/platforms/telosb/hardware.h"
static inline  void TOSH_SET_FLASH_HOLD_PIN()
#line 89
{
#line 89
  extern volatile uint8_t r __asm ("P4OUT");

#line 89
  r |= 1 << 7;
}

#line 88
static inline  void TOSH_MAKE_FLASH_CS_OUTPUT()
#line 88
{
#line 88
  extern volatile uint8_t r __asm ("P4DIR");

#line 88
  r |= 1 << 4;
}

#line 89
static inline  void TOSH_MAKE_FLASH_HOLD_OUTPUT()
#line 89
{
#line 89
  extern volatile uint8_t r __asm ("P4DIR");

#line 89
  r |= 1 << 7;
}

#line 37
static inline  void TOSH_MAKE_UCLK0_OUTPUT()
#line 37
{
#line 37
  extern volatile uint8_t r __asm ("P3DIR");

#line 37
  r |= 1 << 3;
}

#line 36
static inline  void TOSH_MAKE_SIMO0_OUTPUT()
#line 36
{
#line 36
  extern volatile uint8_t r __asm ("P3DIR");

#line 36
  r |= 1 << 1;
}

# 27 "/home/wtiberti/WSN/tinyos/tos/platforms/telosb/MotePlatformC.nc"
static inline void MotePlatformC__TOSH_FLASH_M25P_DP(void )
#line 27
{

  TOSH_MAKE_SIMO0_OUTPUT();
  TOSH_MAKE_UCLK0_OUTPUT();
  TOSH_MAKE_FLASH_HOLD_OUTPUT();
  TOSH_MAKE_FLASH_CS_OUTPUT();
  TOSH_SET_FLASH_HOLD_PIN();
  TOSH_SET_FLASH_CS_PIN();

  MotePlatformC__TOSH_wait();


  TOSH_CLR_FLASH_CS_PIN();
  TOSH_CLR_UCLK0_PIN();

  MotePlatformC__TOSH_FLASH_M25P_DP_bit(TRUE);
  MotePlatformC__TOSH_FLASH_M25P_DP_bit(FALSE);
  MotePlatformC__TOSH_FLASH_M25P_DP_bit(TRUE);
  MotePlatformC__TOSH_FLASH_M25P_DP_bit(TRUE);
  MotePlatformC__TOSH_FLASH_M25P_DP_bit(TRUE);
  MotePlatformC__TOSH_FLASH_M25P_DP_bit(FALSE);
  MotePlatformC__TOSH_FLASH_M25P_DP_bit(FALSE);
  MotePlatformC__TOSH_FLASH_M25P_DP_bit(TRUE);

  TOSH_SET_FLASH_CS_PIN();
  TOSH_SET_UCLK0_PIN();
  TOSH_SET_SIMO0_PIN();
}

#line 6
static __inline void MotePlatformC__uwait(uint16_t u)
#line 6
{
  uint16_t t0 = TAR;

#line 8
  while (TAR - t0 <= u) ;
}

#line 56
static inline error_t MotePlatformC__Init__init(void )
#line 56
{
  /* atomic removed: atomic calls only */

  {
    P1SEL = 0;
    P2SEL = 0;
    P3SEL = 0;
    P4SEL = 0;
    P5SEL = 0;
    P6SEL = 0;

    P1OUT = 0x00;
    P1DIR = 0xe0;

    P2OUT = 0x30;
    P2DIR = 0x7b;

    P3OUT = 0x00;
    P3DIR = 0xf1;

    P4OUT = 0xdd;
    P4DIR = 0xfd;

    P5OUT = 0xff;
    P5DIR = 0xff;

    P6OUT = 0x00;
    P6DIR = 0xff;

    P1IE = 0;
    P2IE = 0;






    MotePlatformC__uwait(1024 * 10);

    MotePlatformC__TOSH_FLASH_M25P_DP();
  }

  return SUCCESS;
}

# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
inline static error_t PlatformP__MoteInit__init(void ){
#line 62
  enum __nesc_unnamed4242 __nesc_result;
#line 62

#line 62
  __nesc_result = MotePlatformC__Init__init();
#line 62

#line 62
  return __nesc_result;
#line 62
}
#line 62
# 327 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/clock_bcs/Msp430ClockP.nc"
static inline void Msp430ClockP__startTimerB(void )
#line 327
{

  Msp430ClockP__TBCTL = 0x0020 | (Msp430ClockP__TBCTL & ~(0x0020 | 0x0010));
}

#line 317
static inline void Msp430ClockP__startTimerA(void )
#line 317
{

  Msp430ClockP__TACTL = 0x0020 | (Msp430ClockP__TACTL & ~(0x0020 | 0x0010));
}

#line 287
static inline void Msp430ClockP__Msp430ClockInit__defaultInitTimerB(void )
#line 287
{
  TBR = 0;









  Msp430ClockP__TBCTL = 0x0100 | 0x0002;
}

#line 313
static inline void Msp430ClockP__Msp430ClockInit__default__initTimerB(void )
#line 313
{
  Msp430ClockP__Msp430ClockInit__defaultInitTimerB();
}

# 43 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/Msp430ClockInit.nc"
inline static void Msp430ClockP__Msp430ClockInit__initTimerB(void ){
#line 43
  Msp430ClockP__Msp430ClockInit__default__initTimerB();
#line 43
}
#line 43
# 275 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/clock_bcs/Msp430ClockP.nc"
static inline void Msp430ClockP__Msp430ClockInit__defaultInitTimerA(void )
#line 275
{
  TAR = 0;







  Msp430ClockP__TACTL = (0x0200 | 0x0000) | 0x0002;
}

#line 309
static inline void Msp430ClockP__Msp430ClockInit__default__initTimerA(void )
#line 309
{
  Msp430ClockP__Msp430ClockInit__defaultInitTimerA();
}

# 42 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/Msp430ClockInit.nc"
inline static void Msp430ClockP__Msp430ClockInit__initTimerA(void ){
#line 42
  Msp430ClockP__Msp430ClockInit__default__initTimerA();
#line 42
}
#line 42
# 253 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/clock_bcs/Msp430ClockP.nc"
static inline void Msp430ClockP__Msp430ClockInit__defaultInitClocks(void )
#line 253
{





  BCSCTL1 = 0x80 | (BCSCTL1 & ((0x01 | 0x02) | 0x04));







  BCSCTL2 = 0x04;




  Msp430ClockP__IE1 &= ~0x02;
}

#line 305
static inline void Msp430ClockP__Msp430ClockInit__default__initClocks(void )
#line 305
{
  Msp430ClockP__Msp430ClockInit__defaultInitClocks();
}

# 41 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/Msp430ClockInit.nc"
inline static void Msp430ClockP__Msp430ClockInit__initClocks(void ){
#line 41
  Msp430ClockP__Msp430ClockInit__default__initClocks();
#line 41
}
#line 41
# 372 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/clock_bcs/Msp430ClockP.nc"
static inline uint16_t Msp430ClockP__test_calib_busywait_delta(uint16_t calib)
#line 372
{
  uint16_t aclk_count = 2;
  uint16_t dco_prev = 0;
  uint16_t dco_curr = 0;

  Msp430ClockP__set_dco_calib(calib);





  while (aclk_count-- > 0) {
      TBCCR0 = TBR + Msp430ClockP__ACLK_CALIB_PERIOD;
      TBCCTL0 &= ~0x0001;
      while ((TBCCTL0 & 0x0001) == 0) {
        }
      dco_prev = dco_curr;
      dco_curr = TAR;
    }
  return dco_curr - dco_prev;
}

#line 408
static inline void Msp430ClockP__busyCalibrateDco(void )
#line 408
{
  uint16_t calib;
  uint16_t step;








  for (calib = 0, step = 0x04 << 8; step; step >>= 1) {

      if (Msp430ClockP__test_calib_busywait_delta(calib | step) <= Msp430ClockP__TARGET_DCO_DELTA) {
        calib |= step;
        }



      if ((calib & 0xe0) == 0xe0) {
        break;
        }
    }
#line 430
  Msp430ClockP__set_dco_calib(calib);
}

#line 232
static inline void Msp430ClockP__Msp430ClockInit__defaultSetupDcoCalibrate(void )
#line 232
{
  Msp430ClockP__TACTL = 0x0200 | 0x0020;
  Msp430ClockP__TBCTL = 0x0100 | 0x0020;








  BCSCTL1 = 0x80 | 0x04;
  BCSCTL2 = 0;
  TBCCTL0 = 0x4000;
}

#line 301
static inline void Msp430ClockP__Msp430ClockInit__default__setupDcoCalibrate(void )
#line 301
{
  Msp430ClockP__Msp430ClockInit__defaultSetupDcoCalibrate();
}

# 40 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/Msp430ClockInit.nc"
inline static void Msp430ClockP__Msp430ClockInit__setupDcoCalibrate(void ){
#line 40
  Msp430ClockP__Msp430ClockInit__default__setupDcoCalibrate();
#line 40
}
#line 40
# 433 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/clock_bcs/Msp430ClockP.nc"
static inline error_t Msp430ClockP__Init__init(void )
#line 433
{
  Msp430ClockP__TACTL = 0x0004;
  Msp430ClockP__TBCTL = 0x0004;
  /* atomic removed: atomic calls only */
  {
    Msp430ClockP__Msp430ClockInit__setupDcoCalibrate();
    Msp430ClockP__busyCalibrateDco();
    Msp430ClockP__Msp430ClockInit__initClocks();
    Msp430ClockP__Msp430ClockInit__initTimerA();
    Msp430ClockP__Msp430ClockInit__initTimerB();
    Msp430ClockP__startTimerA();
    Msp430ClockP__startTimerB();
  }
  return SUCCESS;
}

# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/Init.nc"
inline static error_t PlatformP__MoteClockInit__init(void ){
#line 62
  enum __nesc_unnamed4242 __nesc_result;
#line 62

#line 62
  __nesc_result = Msp430ClockP__Init__init();
#line 62

#line 62
  return __nesc_result;
#line 62
}
#line 62
# 11 "/home/wtiberti/WSN/tinyos/tos/platforms/telosa/PlatformP.nc"
static inline error_t PlatformP__Init__init(void )
#line 11
{
  WDTCTL = 0x5A00 + 0x0080;
  PlatformP__MoteClockInit__init();
  PlatformP__MoteInit__init();
  PlatformP__LedsInit__init();
  return SUCCESS;
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
# 36 "/home/wtiberti/WSN/tinyos/tos/platforms/telosb/hardware.h"
static inline  void TOSH_CLR_SIMO0_PIN()
#line 36
{
#line 36
  extern volatile uint8_t r __asm ("P3OUT");

#line 36
  r &= ~(1 << 1);
}

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
# 24 "/home/wtiberti/WSN/tinyos/tos/platforms/telosa/TelosSerialP.nc"
static inline void TelosSerialP__Resource__granted(void )
#line 24
{
}

# 240 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__Resource__default__granted(uint8_t id)
#line 240
{
}

# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Resource__granted(uint8_t arg_0x7f255726a410){
#line 102
  switch (arg_0x7f255726a410) {
#line 102
    case /*PlatformSerialC.UartC*/Msp430Uart1C__0__CLIENT_ID:
#line 102
      TelosSerialP__Resource__granted();
#line 102
      break;
#line 102
    default:
#line 102
      /*Msp430Uart1P.UartP*/Msp430UartP__0__Resource__default__granted(arg_0x7f255726a410);
#line 102
      break;
#line 102
    }
#line 102
}
#line 102
# 103 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__granted(uint8_t id)
#line 103
{
  /*Msp430Uart1P.UartP*/Msp430UartP__0__Resource__granted(id);
}

# 363 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__default__granted(uint8_t id)
#line 363
{
}

# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__granted(uint8_t arg_0x7f2557ad56a0){
#line 102
  switch (arg_0x7f2557ad56a0) {
#line 102
    case /*PlatformSerialC.UartC.UsartC*/Msp430Usart1C__0__CLIENT_ID:
#line 102
      /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__granted(/*PlatformSerialC.UartC*/Msp430Uart1C__0__CLIENT_ID);
#line 102
      break;
#line 102
    default:
#line 102
      /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__default__granted(arg_0x7f2557ad56a0);
#line 102
      break;
#line 102
    }
#line 102
}
#line 102
# 367 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceConfigure__default__configure(uint8_t id)
#line 367
{
}

# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
inline static void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceConfigure__configure(uint8_t arg_0x7f2557ad06b0){
#line 59
  switch (arg_0x7f2557ad06b0) {
#line 59
    case /*PlatformSerialC.UartC.UsartC*/Msp430Usart1C__0__CLIENT_ID:
#line 59
      /*Msp430Uart1P.UartP*/Msp430UartP__0__ResourceConfigure__configure(/*PlatformSerialC.UartC*/Msp430Uart1C__0__CLIENT_ID);
#line 59
      break;
#line 59
    default:
#line 59
      /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceConfigure__default__configure(arg_0x7f2557ad06b0);
#line 59
      break;
#line 59
    }
#line 59
}
#line 59
# 346 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__grantedTask__runTask(void )
#line 346
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 347
    {
      /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__resId = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__reqResId;
      /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__reqResId = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__NO_RES;
      /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__state = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__RES_BUSY;
    }
#line 351
    __nesc_atomic_end(__nesc_atomic); }



  /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceConfigure__configure(/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__resId);
  /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__granted(/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__resId);
}

# 26 "/home/wtiberti/WSN/tinyos/tos/platforms/telosa/TelosSerialP.nc"
static inline const msp430_uart_union_config_t *TelosSerialP__Msp430UartConfigure__getConfig(void )
#line 26
{
  return &TelosSerialP__msp430_uart_telos_config;
}

# 236 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline const msp430_uart_union_config_t */*Msp430Uart1P.UartP*/Msp430UartP__0__Msp430UartConfigure__default__getConfig(uint8_t id)
#line 236
{
  return &msp430_uart_default_config;
}

# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartConfigure.nc"
inline static const msp430_uart_union_config_t */*Msp430Uart1P.UartP*/Msp430UartP__0__Msp430UartConfigure__getConfig(uint8_t arg_0x7f2557262020){
#line 39
  union __nesc_unnamed4289 const *__nesc_result;
#line 39

#line 39
  switch (arg_0x7f2557262020) {
#line 39
    case /*PlatformSerialC.UartC*/Msp430Uart1C__0__CLIENT_ID:
#line 39
      __nesc_result = TelosSerialP__Msp430UartConfigure__getConfig();
#line 39
      break;
#line 39
    default:
#line 39
      __nesc_result = /*Msp430Uart1P.UartP*/Msp430UartP__0__Msp430UartConfigure__default__getConfig(arg_0x7f2557262020);
#line 39
      break;
#line 39
    }
#line 39

#line 39
  return __nesc_result;
#line 39
}
#line 39
# 331 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
static inline void HplMsp430Usart1P__Usart__clrIntr(void )
#line 331
{
  HplMsp430Usart1P__IFG2 &= ~(0x20 | 0x10);
}









static inline void HplMsp430Usart1P__Usart__disableIntr(void )
#line 343
{
  HplMsp430Usart1P__IE2 &= ~(0x20 | 0x10);
}

#line 145
static inline void HplMsp430Usart1P__Usart__resetUsart(bool reset)
#line 145
{
  if (reset) {
    U1CTL = 0x01;
    }
  else {
#line 149
    U1CTL &= ~0x01;
    }
}

# 106 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P37*/HplMsp430GeneralIOP__23__IO__selectIOFunc(void )
#line 106
{
  /* atomic removed: atomic calls only */
#line 106
  * (volatile uint8_t * )27U &= ~(0x01 << 7);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart1P__URXD__selectIOFunc(void ){
#line 97
  /*HplMsp430GeneralIOC.P37*/HplMsp430GeneralIOP__23__IO__selectIOFunc();
#line 97
}
#line 97
# 106 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P36*/HplMsp430GeneralIOP__22__IO__selectIOFunc(void )
#line 106
{
  /* atomic removed: atomic calls only */
#line 106
  * (volatile uint8_t * )27U &= ~(0x01 << 6);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart1P__UTXD__selectIOFunc(void ){
#line 97
  /*HplMsp430GeneralIOC.P36*/HplMsp430GeneralIOP__22__IO__selectIOFunc();
#line 97
}
#line 97
# 197 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
static inline void HplMsp430Usart1P__Usart__disableUart(void )
#line 197
{
  /* atomic removed: atomic calls only */
#line 198
  {
    HplMsp430Usart1P__ME2 &= ~(0x20 | 0x10);
    HplMsp430Usart1P__UTXD__selectIOFunc();
    HplMsp430Usart1P__URXD__selectIOFunc();
  }
}

# 104 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P36*/HplMsp430GeneralIOP__22__IO__selectModuleFunc(void )
#line 104
{
  /* atomic removed: atomic calls only */
#line 104
  * (volatile uint8_t * )27U |= 0x01 << 6;
}

# 91 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart1P__UTXD__selectModuleFunc(void ){
#line 91
  /*HplMsp430GeneralIOC.P36*/HplMsp430GeneralIOP__22__IO__selectModuleFunc();
#line 91
}
#line 91
# 206 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
static inline void HplMsp430Usart1P__Usart__enableUartTx(void )
#line 206
{
  HplMsp430Usart1P__UTXD__selectModuleFunc();
  HplMsp430Usart1P__ME2 |= 0x20;
}

#line 222
static inline void HplMsp430Usart1P__Usart__disableUartRx(void )
#line 222
{
  HplMsp430Usart1P__ME2 &= ~0x10;
  HplMsp430Usart1P__URXD__selectIOFunc();
}

# 104 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P37*/HplMsp430GeneralIOP__23__IO__selectModuleFunc(void )
#line 104
{
  /* atomic removed: atomic calls only */
#line 104
  * (volatile uint8_t * )27U |= 0x01 << 7;
}

# 91 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart1P__URXD__selectModuleFunc(void ){
#line 91
  /*HplMsp430GeneralIOC.P37*/HplMsp430GeneralIOP__23__IO__selectModuleFunc();
#line 91
}
#line 91
# 217 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
static inline void HplMsp430Usart1P__Usart__enableUartRx(void )
#line 217
{
  HplMsp430Usart1P__URXD__selectModuleFunc();
  HplMsp430Usart1P__ME2 |= 0x10;
}

#line 211
static inline void HplMsp430Usart1P__Usart__disableUartTx(void )
#line 211
{
  HplMsp430Usart1P__ME2 &= ~0x20;
  HplMsp430Usart1P__UTXD__selectIOFunc();
}

#line 189
static inline void HplMsp430Usart1P__Usart__enableUart(void )
#line 189
{
  /* atomic removed: atomic calls only */
#line 190
  {
    HplMsp430Usart1P__UTXD__selectModuleFunc();
    HplMsp430Usart1P__URXD__selectModuleFunc();
  }
  HplMsp430Usart1P__ME2 |= 0x20 | 0x10;
}

#line 137
static inline void HplMsp430Usart1P__Usart__setUmctl(uint8_t control)
#line 137
{
  U1MCTL = control;
}

#line 126
static inline void HplMsp430Usart1P__Usart__setUbr(uint16_t control)
#line 126
{
  /* atomic removed: atomic calls only */
#line 127
  {
    U1BR0 = control & 0x00FF;
    U1BR1 = (control >> 8) & 0x00FF;
  }
}

#line 269
static inline void HplMsp430Usart1P__configUart(const msp430_uart_union_config_t *config)
#line 269
{

  U1CTL = (config->uartRegisters.uctl & ~0x04) | 0x01;
  HplMsp430Usart1P__U1TCTL = config->uartRegisters.utctl;
  HplMsp430Usart1P__U1RCTL = config->uartRegisters.urctl;

  HplMsp430Usart1P__Usart__setUbr(config->uartRegisters.ubr);
  HplMsp430Usart1P__Usart__setUmctl(config->uartRegisters.umctl);
}

# 106 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P53*/HplMsp430GeneralIOP__35__IO__selectIOFunc(void )
#line 106
{
  /* atomic removed: atomic calls only */
#line 106
  * (volatile uint8_t * )51U &= ~(0x01 << 3);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart1P__UCLK__selectIOFunc(void ){
#line 97
  /*HplMsp430GeneralIOC.P53*/HplMsp430GeneralIOP__35__IO__selectIOFunc();
#line 97
}
#line 97
# 106 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P52*/HplMsp430GeneralIOP__34__IO__selectIOFunc(void )
#line 106
{
  /* atomic removed: atomic calls only */
#line 106
  * (volatile uint8_t * )51U &= ~(0x01 << 2);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart1P__SOMI__selectIOFunc(void ){
#line 97
  /*HplMsp430GeneralIOC.P52*/HplMsp430GeneralIOP__34__IO__selectIOFunc();
#line 97
}
#line 97
# 106 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P51*/HplMsp430GeneralIOP__33__IO__selectIOFunc(void )
#line 106
{
  /* atomic removed: atomic calls only */
#line 106
  * (volatile uint8_t * )51U &= ~(0x01 << 1);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart1P__SIMO__selectIOFunc(void ){
#line 97
  /*HplMsp430GeneralIOC.P51*/HplMsp430GeneralIOP__33__IO__selectIOFunc();
#line 97
}
#line 97
# 237 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
static inline void HplMsp430Usart1P__Usart__disableSpi(void )
#line 237
{
  /* atomic removed: atomic calls only */
#line 238
  {
    HplMsp430Usart1P__ME2 &= ~0x10;
    HplMsp430Usart1P__SIMO__selectIOFunc();
    HplMsp430Usart1P__SOMI__selectIOFunc();
    HplMsp430Usart1P__UCLK__selectIOFunc();
  }
}

#line 279
static inline void HplMsp430Usart1P__Usart__setModeUart(const msp430_uart_union_config_t *config)
#line 279
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 280
    {
      HplMsp430Usart1P__Usart__resetUsart(TRUE);
      HplMsp430Usart1P__Usart__disableSpi();
      HplMsp430Usart1P__configUart(config);
      if (config->uartConfig.utxe == 1 && config->uartConfig.urxe == 1) {
          HplMsp430Usart1P__Usart__enableUart();
        }
      else {
#line 286
        if (config->uartConfig.utxe == 0 && config->uartConfig.urxe == 1) {
            HplMsp430Usart1P__Usart__disableUartTx();
            HplMsp430Usart1P__Usart__enableUartRx();
          }
        else {
#line 289
          if (config->uartConfig.utxe == 1 && config->uartConfig.urxe == 0) {
              HplMsp430Usart1P__Usart__disableUartRx();
              HplMsp430Usart1P__Usart__enableUartTx();
            }
          else 
#line 292
            {
              HplMsp430Usart1P__Usart__disableUart();
            }
          }
        }
#line 295
      HplMsp430Usart1P__Usart__resetUsart(FALSE);
      HplMsp430Usart1P__Usart__disableIntr();
      HplMsp430Usart1P__Usart__clrIntr();
    }
#line 298
    __nesc_atomic_end(__nesc_atomic); }
  return;
}

# 174 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__setModeUart(const msp430_uart_union_config_t *config){
#line 174
  HplMsp430Usart1P__Usart__setModeUart(config);
#line 174
}
#line 174
# 361 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
static inline void HplMsp430Usart1P__Usart__enableIntr(void )
#line 361
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 362
    {
      HplMsp430Usart1P__IFG2 &= ~(0x20 | 0x10);
      HplMsp430Usart1P__IE2 |= 0x20 | 0x10;
    }
#line 365
    __nesc_atomic_end(__nesc_atomic); }
}

# 182 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__enableIntr(void ){
#line 182
  HplMsp430Usart1P__Usart__enableIntr();
#line 182
}
#line 182
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
inline static void /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__sendDone(uint8_t arg_0x7f2557438960, message_t * msg, error_t error){
#line 100
  switch (arg_0x7f2557438960) {
#line 100
    case 0U:
#line 100
      /*BlinkToRadioAppC.AMSenderC.SenderC.AMQueueEntryP*/AMQueueEntryP__0__Send__sendDone(msg, error);
#line 100
      break;
#line 100
    default:
#line 100
      /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__Send__default__sendDone(arg_0x7f2557438960, msg, error);
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
inline static error_t /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMSend__send(am_id_t arg_0x7f2557435510, am_addr_t addr, message_t * msg, uint8_t len){
#line 80
  enum __nesc_unnamed4242 __nesc_result;
#line 80

#line 80
  __nesc_result = CC2420ActiveMessageP__AMSend__send(arg_0x7f2557435510, addr, msg, len);
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
inline static void CC2420ActiveMessageP__SendNotifier__aboutToSend(am_id_t arg_0x7f25574f9b30, am_addr_t dest, message_t * msg){
#line 59
    CC2420ActiveMessageP__SendNotifier__default__aboutToSend(arg_0x7f25574f9b30, dest, msg);
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
inline static void CC2420ActiveMessageP__RadioBackoff__requestCca(am_id_t arg_0x7f25574f8700, message_t * msg){
#line 95
    CC2420ActiveMessageP__RadioBackoff__default__requestCca(arg_0x7f25574f8700, msg);
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
# 338 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__isOwner(uint8_t id)
#line 338
{
  /* atomic removed: atomic calls only */
#line 339
  {
    unsigned char __nesc_temp = 
#line 339
    /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId == id && /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state == /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_BUSY;

#line 339
    return __nesc_temp;
  }
}

# 172 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline bool /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__isOwner(uint8_t id)
#line 172
{
#line 172
  return FALSE;
}

# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static bool /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__isOwner(uint8_t arg_0x7f2557c8a980){
#line 128
  unsigned char __nesc_result;
#line 128

#line 128
  switch (arg_0x7f2557c8a980) {
#line 128
    case /*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID:
#line 128
      __nesc_result = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__isOwner(/*CC2420SpiWireC.HplCC2420SpiC.SpiC.UsartC*/Msp430Usart0C__0__CLIENT_ID);
#line 128
      break;
#line 128
    default:
#line 128
      __nesc_result = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__isOwner(arg_0x7f2557c8a980);
#line 128
      break;
#line 128
    }
#line 128

#line 128
  return __nesc_result;
#line 128
}
#line 128
# 112 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline bool /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__isOwner(uint8_t id)
#line 112
{
  return /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__isOwner(id);
}

# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static bool CC2420SpiP__SpiResource__isOwner(void ){
#line 128
  unsigned char __nesc_result;
#line 128

#line 128
  __nesc_result = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__isOwner(/*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID);
#line 128

#line 128
  return __nesc_result;
#line 128
}
#line 128
# 176 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline const msp430_spi_union_config_t */*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Msp430SpiConfigure__default__getConfig(uint8_t id)
#line 176
{
  return &msp430_spi_default_config;
}

# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiConfigure.nc"
inline static const msp430_spi_union_config_t */*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Msp430SpiConfigure__getConfig(uint8_t arg_0x7f2557c89d40){
#line 39
  union __nesc_unnamed4285 const *__nesc_result;
#line 39

#line 39
    __nesc_result = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Msp430SpiConfigure__default__getConfig(arg_0x7f2557c89d40);
#line 39

#line 39
  return __nesc_result;
#line 39
}
#line 39
# 168 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__setModeSpi(const msp430_spi_union_config_t *config){
#line 168
  HplMsp430Usart0P__Usart__setModeSpi(config);
#line 168
}
#line 168
# 120 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__ResourceConfigure__configure(uint8_t id)
#line 120
{
  /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__setModeSpi(/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Msp430SpiConfigure__getConfig(id));
}

# 367 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__default__configure(uint8_t id)
#line 367
{
}

# 59 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
inline static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__configure(uint8_t arg_0x7f2557ad06b0){
#line 59
  switch (arg_0x7f2557ad06b0) {
#line 59
    case /*CC2420SpiWireC.HplCC2420SpiC.SpiC.UsartC*/Msp430Usart0C__0__CLIENT_ID:
#line 59
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__ResourceConfigure__configure(/*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID);
#line 59
      break;
#line 59
    default:
#line 59
      /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__default__configure(arg_0x7f2557ad06b0);
#line 59
      break;
#line 59
    }
#line 59
}
#line 59
# 374 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__default__immediateRequested(void )
#line 374
{
  /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__release();
}

# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwner.nc"
inline static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__immediateRequested(void ){
#line 79
  /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__default__immediateRequested();
#line 79
}
#line 79
# 365 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__default__immediateRequested(uint8_t id)
#line 365
{
}

# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
inline static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__immediateRequested(uint8_t arg_0x7f2557ad49d0){
#line 61
    /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__default__immediateRequested(arg_0x7f2557ad49d0);
#line 61
}
#line 61
# 222 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__immediateRequest(uint8_t id)
#line 222
{
  /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__immediateRequested(/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId);
  /* atomic removed: atomic calls only */
#line 224
  {




    if (/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state != /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_DEF_OWNED) 
      {
        enum __nesc_unnamed4242 __nesc_temp = 
#line 230
        FAIL;

#line 230
        return __nesc_temp;
      }
#line 231
    /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_IMM_GRANTING;
    /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__reqResId = id;
  }
  /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__immediateRequested();
  if (/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId == id) {
      /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__configure(/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId);
      return SUCCESS;
    }
  /* atomic removed: atomic calls only */





  /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_DEF_OWNED;
  return FAIL;
}

# 174 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__immediateRequest(uint8_t id)
#line 174
{
#line 174
  return FAIL;
}

# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__immediateRequest(uint8_t arg_0x7f2557c8a980){
#line 97
  enum __nesc_unnamed4242 __nesc_result;
#line 97

#line 97
  switch (arg_0x7f2557c8a980) {
#line 97
    case /*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID:
#line 97
      __nesc_result = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__immediateRequest(/*CC2420SpiWireC.HplCC2420SpiC.SpiC.UsartC*/Msp430Usart0C__0__CLIENT_ID);
#line 97
      break;
#line 97
    default:
#line 97
      __nesc_result = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__immediateRequest(arg_0x7f2557c8a980);
#line 97
      break;
#line 97
    }
#line 97

#line 97
  return __nesc_result;
#line 97
}
#line 97
# 104 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__immediateRequest(uint8_t id)
#line 104
{
  return /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__immediateRequest(id);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420SpiP__SpiResource__immediateRequest(void ){
#line 97
  enum __nesc_unnamed4242 __nesc_result;
#line 97

#line 97
  __nesc_result = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__immediateRequest(/*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID);
#line 97

#line 97
  return __nesc_result;
#line 97
}
#line 97
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

# 137 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
static inline void HplMsp430Usart0P__Usart__resetUsart(bool reset)
#line 137
{
  if (reset) {
      U0CTL = 0x01;
    }
  else {
      U0CTL &= ~0x01;
    }
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void HplMsp430I2C0P__HplUsart__resetUsart(bool reset){
#line 97
  HplMsp430Usart0P__Usart__resetUsart(reset);
#line 97
}
#line 97
# 68 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430I2C0P.nc"
static inline void HplMsp430I2C0P__HplI2C__clearModeI2C(void )
#line 68
{
  /* atomic removed: atomic calls only */
#line 69
  {
    HplMsp430I2C0P__U0CTL &= ~((0x20 | 0x04) | 0x01);
    HplMsp430I2C0P__HplUsart__resetUsart(TRUE);
  }
}

# 7 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430I2C.nc"
inline static void HplMsp430Usart0P__HplI2C__clearModeI2C(void ){
#line 7
  HplMsp430I2C0P__HplI2C__clearModeI2C();
#line 7
}
#line 7
# 106 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P35*/HplMsp430GeneralIOP__21__IO__selectIOFunc(void )
#line 106
{
  /* atomic removed: atomic calls only */
#line 106
  * (volatile uint8_t * )27U &= ~(0x01 << 5);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart0P__URXD__selectIOFunc(void ){
#line 97
  /*HplMsp430GeneralIOC.P35*/HplMsp430GeneralIOP__21__IO__selectIOFunc();
#line 97
}
#line 97
# 106 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P34*/HplMsp430GeneralIOP__20__IO__selectIOFunc(void )
#line 106
{
  /* atomic removed: atomic calls only */
#line 106
  * (volatile uint8_t * )27U &= ~(0x01 << 4);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart0P__UTXD__selectIOFunc(void ){
#line 97
  /*HplMsp430GeneralIOC.P34*/HplMsp430GeneralIOP__20__IO__selectIOFunc();
#line 97
}
#line 97
# 193 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
static inline void HplMsp430Usart0P__Usart__disableUart(void )
#line 193
{
  /* atomic removed: atomic calls only */
#line 194
  {
    HplMsp430Usart0P__ME1 &= ~(0x80 | 0x40);
    HplMsp430Usart0P__UTXD__selectIOFunc();
    HplMsp430Usart0P__URXD__selectIOFunc();
  }
}

#line 129
static inline void HplMsp430Usart0P__Usart__setUmctl(uint8_t control)
#line 129
{
  U0MCTL = control;
}

#line 118
static inline void HplMsp430Usart0P__Usart__setUbr(uint16_t control)
#line 118
{
  /* atomic removed: atomic calls only */
#line 119
  {
    U0BR0 = control & 0x00FF;
    U0BR1 = (control >> 8) & 0x00FF;
  }
}

#line 242
static inline void HplMsp430Usart0P__configSpi(const msp430_spi_union_config_t *config)
#line 242
{

  U0CTL = (config->spiRegisters.uctl | 0x04) | 0x01;
  HplMsp430Usart0P__U0TCTL = config->spiRegisters.utctl;

  HplMsp430Usart0P__Usart__setUbr(config->spiRegisters.ubr);
  HplMsp430Usart0P__Usart__setUmctl(0x00);
}

# 104 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P33*/HplMsp430GeneralIOP__19__IO__selectModuleFunc(void )
#line 104
{
  /* atomic removed: atomic calls only */
#line 104
  * (volatile uint8_t * )27U |= 0x01 << 3;
}

# 91 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart0P__UCLK__selectModuleFunc(void ){
#line 91
  /*HplMsp430GeneralIOC.P33*/HplMsp430GeneralIOP__19__IO__selectModuleFunc();
#line 91
}
#line 91
# 104 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P32*/HplMsp430GeneralIOP__18__IO__selectModuleFunc(void )
#line 104
{
  /* atomic removed: atomic calls only */
#line 104
  * (volatile uint8_t * )27U |= 0x01 << 2;
}

# 91 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart0P__SOMI__selectModuleFunc(void ){
#line 91
  /*HplMsp430GeneralIOC.P32*/HplMsp430GeneralIOP__18__IO__selectModuleFunc();
#line 91
}
#line 91
# 104 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P31*/HplMsp430GeneralIOP__17__IO__selectModuleFunc(void )
#line 104
{
  /* atomic removed: atomic calls only */
#line 104
  * (volatile uint8_t * )27U |= 0x01 << 1;
}

# 91 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart0P__SIMO__selectModuleFunc(void ){
#line 91
  /*HplMsp430GeneralIOC.P31*/HplMsp430GeneralIOP__17__IO__selectModuleFunc();
#line 91
}
#line 91
# 224 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
static inline void HplMsp430Usart0P__Usart__enableSpi(void )
#line 224
{
  /* atomic removed: atomic calls only */
#line 225
  {
    HplMsp430Usart0P__SIMO__selectModuleFunc();
    HplMsp430Usart0P__SOMI__selectModuleFunc();
    HplMsp430Usart0P__UCLK__selectModuleFunc();
  }
  HplMsp430Usart0P__ME1 |= 0x40;
}

#line 328
static inline void HplMsp430Usart0P__Usart__clrIntr(void )
#line 328
{
  HplMsp430Usart0P__IFG1 &= ~(0x80 | 0x40);
}









static inline void HplMsp430Usart0P__Usart__disableIntr(void )
#line 340
{
  HplMsp430Usart0P__IE1 &= ~(0x80 | 0x40);
}

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
# 370 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__default__requested(void )
#line 370
{
  /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__release();
}

# 71 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwner.nc"
inline static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__requested(void ){
#line 71
  /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__default__requested();
#line 71
}
#line 71
# 70 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
inline static resource_client_id_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Queue__dequeue(void ){
#line 70
  unsigned char __nesc_result;
#line 70

#line 70
  __nesc_result = /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__dequeue();
#line 70

#line 70
  return __nesc_result;
#line 70
}
#line 70
# 364 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__default__requested(uint8_t id)
#line 364
{
}

# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
inline static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__requested(uint8_t arg_0x7f2557ad49d0){
#line 53
    /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__default__requested(arg_0x7f2557ad49d0);
#line 53
}
#line 53
# 64 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
static inline bool /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEnqueued(resource_client_id_t id)
#line 64
{
  /* atomic removed: atomic calls only */
#line 65
  {
    unsigned char __nesc_temp = 
#line 65
    /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__resQ[id] != /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__NO_ENTRY || /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qTail == id;

#line 65
    return __nesc_temp;
  }
}

#line 82
static inline error_t /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__enqueue(resource_client_id_t id)
#line 82
{
  /* atomic removed: atomic calls only */
#line 83
  {
    if (!/*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEnqueued(id)) {
        if (/*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qHead == /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__NO_ENTRY) {
          /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qHead = id;
          }
        else {
#line 88
          /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__resQ[/*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qTail] = id;
          }
#line 89
        /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qTail = id;
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
inline static error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Queue__enqueue(resource_client_id_t id){
#line 79
  enum __nesc_unnamed4242 __nesc_result;
#line 79

#line 79
  __nesc_result = /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__enqueue(id);
#line 79

#line 79
  return __nesc_result;
#line 79
}
#line 79
# 157 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__request(uint8_t id)
#line 157
{
  error_t rval;

  /* atomic removed: atomic calls only */





  {
#line 188
    if (/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__reqResId == id) 
      {
        enum __nesc_unnamed4242 __nesc_temp = 
#line 189
        EBUSY;

#line 189
        return __nesc_temp;
      }
#line 190
    if ((rval = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Queue__enqueue(id))) 
      {
        enum __nesc_unnamed4242 __nesc_temp = 
#line 191
        rval;

#line 191
        return __nesc_temp;
      }
  }
  /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceRequested__requested(/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId);
  /* atomic removed: atomic calls only */






  {




    if (/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state != /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_DEF_OWNED) 
      {
        enum __nesc_unnamed4242 __nesc_temp = 
#line 208
        SUCCESS;

#line 208
        return __nesc_temp;
      }





    /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_PREGRANT;
    /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__reqResId = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Queue__dequeue();
  }
  /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__requested();
  return SUCCESS;
}

# 173 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__request(uint8_t id)
#line 173
{
#line 173
  return FAIL;
}

# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__request(uint8_t arg_0x7f2557c8a980){
#line 88
  enum __nesc_unnamed4242 __nesc_result;
#line 88

#line 88
  switch (arg_0x7f2557c8a980) {
#line 88
    case /*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID:
#line 88
      __nesc_result = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__request(/*CC2420SpiWireC.HplCC2420SpiC.SpiC.UsartC*/Msp430Usart0C__0__CLIENT_ID);
#line 88
      break;
#line 88
    default:
#line 88
      __nesc_result = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__request(arg_0x7f2557c8a980);
#line 88
      break;
#line 88
    }
#line 88

#line 88
  return __nesc_result;
#line 88
}
#line 88
# 108 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__request(uint8_t id)
#line 108
{
  return /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__request(id);
}

# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420SpiP__SpiResource__request(void ){
#line 88
  enum __nesc_unnamed4242 __nesc_result;
#line 88

#line 88
  __nesc_result = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__request(/*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID);
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
# 365 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
static inline void HplMsp430Usart0P__Usart__tx(uint8_t data)
#line 365
{
  HplMsp430Usart0P__U0TXBUF = data;
}

# 220 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__tx(uint8_t data){
#line 220
  HplMsp430Usart0P__Usart__tx(data);
#line 220
}
#line 220
# 313 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
static inline bool HplMsp430Usart0P__Usart__isRxIntrPending(void )
#line 313
{
  if (HplMsp430Usart0P__IFG1 & 0x40) {
      return TRUE;
    }
  return FALSE;
}

# 192 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static bool /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__isRxIntrPending(void ){
#line 192
  unsigned char __nesc_result;
#line 192

#line 192
  __nesc_result = HplMsp430Usart0P__Usart__isRxIntrPending();
#line 192

#line 192
  return __nesc_result;
#line 192
}
#line 192
# 324 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
static inline void HplMsp430Usart0P__Usart__clrRxIntr(void )
#line 324
{
  HplMsp430Usart0P__IFG1 &= ~0x40;
}

# 197 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__clrRxIntr(void ){
#line 197
  HplMsp430Usart0P__Usart__clrRxIntr();
#line 197
}
#line 197
# 369 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
static inline uint8_t HplMsp430Usart0P__Usart__rx(void )
#line 369
{
  return U0RXBUF;
}

# 227 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static uint8_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__rx(void ){
#line 227
  unsigned char __nesc_result;
#line 227

#line 227
  __nesc_result = HplMsp430Usart0P__Usart__rx();
#line 227

#line 227
  return __nesc_result;
#line 227
}
#line 227
# 76 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
inline static error_t CC2420SpiP__SpiPacket__send(uint8_t * txBuf, uint8_t * rxBuf, uint16_t len){
#line 76
  enum __nesc_unnamed4242 __nesc_result;
#line 76

#line 76
  __nesc_result = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiPacket__send(/*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID, txBuf, rxBuf, len);
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
  __nesc_result = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiByte__write(tx);
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
# 344 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
static inline void HplMsp430Usart0P__Usart__enableRxIntr(void )
#line 344
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 345
    {
      HplMsp430Usart0P__IFG1 &= ~0x40;
      HplMsp430Usart0P__IE1 |= 0x40;
    }
#line 348
    __nesc_atomic_end(__nesc_atomic); }
}

# 180 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__enableRxIntr(void ){
#line 180
  HplMsp430Usart0P__Usart__enableRxIntr();
#line 180
}
#line 180
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone_task__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone_task);
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
inline static void CC2420TinyosNetworkP__Resource__granted(uint8_t arg_0x7f255758f600){
#line 102
  switch (arg_0x7f255758f600) {
#line 102
    case CC2420ActiveMessageC__CC2420_AM_SEND_ID:
#line 102
      CC2420ActiveMessageP__RadioResource__granted();
#line 102
      break;
#line 102
    default:
#line 102
      CC2420TinyosNetworkP__Resource__default__granted(arg_0x7f255758f600);
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
inline static message_t * CC2420ActiveMessageP__Snoop__receive(am_id_t arg_0x7f25574fcc40, message_t * msg, void * payload, uint8_t len){
#line 78
  nx_struct message_t *__nesc_result;
#line 78

#line 78
    __nesc_result = CC2420ActiveMessageP__Snoop__default__receive(arg_0x7f25574fcc40, msg, payload, len);
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
# 96 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P56*/HplMsp430GeneralIOP__38__IO__clr(void )
#line 96
{
#line 96
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 96
    * (volatile uint8_t * )49U &= ~(0x01 << 6);
#line 96
    __nesc_atomic_end(__nesc_atomic); }
}

# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__HplGeneralIO__clr(void ){
#line 54
  /*HplMsp430GeneralIOC.P56*/HplMsp430GeneralIOP__38__IO__clr();
#line 54
}
#line 54
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__GeneralIO__clr(void )
#line 49
{
#line 49
  /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__HplGeneralIO__clr();
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led2__clr(void ){
#line 41
  /*PlatformLedsC.Led2Impl*/Msp430GpioC__2__GeneralIO__clr();
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
# 96 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P55*/HplMsp430GeneralIOP__37__IO__clr(void )
#line 96
{
#line 96
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 96
    * (volatile uint8_t * )49U &= ~(0x01 << 5);
#line 96
    __nesc_atomic_end(__nesc_atomic); }
}

# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__HplGeneralIO__clr(void ){
#line 54
  /*HplMsp430GeneralIOC.P55*/HplMsp430GeneralIOP__37__IO__clr();
#line 54
}
#line 54
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__GeneralIO__clr(void )
#line 49
{
#line 49
  /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__HplGeneralIO__clr();
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led1__clr(void ){
#line 41
  /*PlatformLedsC.Led1Impl*/Msp430GpioC__1__GeneralIO__clr();
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
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__HplGeneralIO__clr(void ){
#line 54
  /*HplMsp430GeneralIOC.P54*/HplMsp430GeneralIOP__36__IO__clr();
#line 54
}
#line 54
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__GeneralIO__clr(void )
#line 49
{
#line 49
  /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__HplGeneralIO__clr();
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void LedsP__Led0__clr(void ){
#line 41
  /*PlatformLedsC.Led0Impl*/Msp430GpioC__0__GeneralIO__clr();
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
inline static message_t * CC2420ActiveMessageP__Receive__receive(am_id_t arg_0x7f25574fc060, message_t * msg, void * payload, uint8_t len){
#line 78
  nx_struct message_t *__nesc_result;
#line 78

#line 78
  switch (arg_0x7f25574fc060) {
#line 78
    case 6:
#line 78
      __nesc_result = BlinkToRadioC__Receive__receive(msg, payload, len);
#line 78
      break;
#line 78
    default:
#line 78
      __nesc_result = CC2420ActiveMessageP__Receive__default__receive(arg_0x7f25574fc060, msg, payload, len);
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
# 158 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__disableSpi(void ){
#line 158
  HplMsp430Usart0P__Usart__disableSpi();
#line 158
}
#line 158
#line 97
inline static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__resetUsart(bool reset){
#line 97
  HplMsp430Usart0P__Usart__resetUsart(reset);
#line 97
}
#line 97
# 124 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__ResourceConfigure__unconfigure(uint8_t id)
#line 124
{
  /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__resetUsart(TRUE);
  /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__disableSpi();
}

# 368 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__default__unconfigure(uint8_t id)
#line 368
{
}

# 65 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceConfigure.nc"
inline static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__unconfigure(uint8_t arg_0x7f2557ad06b0){
#line 65
  switch (arg_0x7f2557ad06b0) {
#line 65
    case /*CC2420SpiWireC.HplCC2420SpiC.SpiC.UsartC*/Msp430Usart0C__0__CLIENT_ID:
#line 65
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__ResourceConfigure__unconfigure(/*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID);
#line 65
      break;
#line 65
    default:
#line 65
      /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__default__unconfigure(arg_0x7f2557ad06b0);
#line 65
      break;
#line 65
    }
#line 65
}
#line 65
# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__grantedTask__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__grantedTask);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 366 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__default__granted(void )
#line 366
{
}

# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwner.nc"
inline static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__granted(void ){
#line 44
  /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__default__granted();
#line 44
}
#line 44
# 60 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
static inline bool /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEmpty(void )
#line 60
{
  /* atomic removed: atomic calls only */
#line 61
  {
    unsigned char __nesc_temp = 
#line 61
    /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qHead == /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__NO_ENTRY;

#line 61
    return __nesc_temp;
  }
}

# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceQueue.nc"
inline static bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Queue__isEmpty(void ){
#line 53
  unsigned char __nesc_result;
#line 53

#line 53
  __nesc_result = /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__isEmpty();
#line 53

#line 53
  return __nesc_result;
#line 53
}
#line 53
# 249 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__release(uint8_t id)
#line 249
{
  /* atomic removed: atomic calls only */


  {
    if (/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state == /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_BUSY && /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId == id) {
        if (/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Queue__isEmpty()) {




            /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__default_owner_id;
            /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_DEF_OWNED;
            /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__unconfigure(id);
            /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__granted();
          }
        else 
#line 264
          {






            /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__reqResId = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Queue__dequeue();
            /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__NO_RES;
            /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_GRANTING;
            /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__grantedTask__postTask();
            /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__unconfigure(id);
          }
        {
          enum __nesc_unnamed4242 __nesc_temp = 
#line 277
          SUCCESS;

#line 277
          return __nesc_temp;
        }
      }
  }
#line 280
  return FAIL;
}

# 175 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__release(uint8_t id)
#line 175
{
#line 175
  return FAIL;
}

# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__release(uint8_t arg_0x7f2557c8a980){
#line 120
  enum __nesc_unnamed4242 __nesc_result;
#line 120

#line 120
  switch (arg_0x7f2557c8a980) {
#line 120
    case /*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID:
#line 120
      __nesc_result = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__release(/*CC2420SpiWireC.HplCC2420SpiC.SpiC.UsartC*/Msp430Usart0C__0__CLIENT_ID);
#line 120
      break;
#line 120
    default:
#line 120
      __nesc_result = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__default__release(arg_0x7f2557c8a980);
#line 120
      break;
#line 120
    }
#line 120

#line 120
  return __nesc_result;
#line 120
}
#line 120
# 116 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__release(uint8_t id)
#line 116
{
  return /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__release(id);
}

# 120 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t CC2420SpiP__SpiResource__release(void ){
#line 120
  enum __nesc_unnamed4242 __nesc_result;
#line 120

#line 120
  __nesc_result = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__release(/*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID);
#line 120

#line 120
  return __nesc_result;
#line 120
}
#line 120
# 106 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P31*/HplMsp430GeneralIOP__17__IO__selectIOFunc(void )
#line 106
{
  /* atomic removed: atomic calls only */
#line 106
  * (volatile uint8_t * )27U &= ~(0x01 << 1);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart0P__SIMO__selectIOFunc(void ){
#line 97
  /*HplMsp430GeneralIOC.P31*/HplMsp430GeneralIOP__17__IO__selectIOFunc();
#line 97
}
#line 97
# 106 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P32*/HplMsp430GeneralIOP__18__IO__selectIOFunc(void )
#line 106
{
  /* atomic removed: atomic calls only */
#line 106
  * (volatile uint8_t * )27U &= ~(0x01 << 2);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart0P__SOMI__selectIOFunc(void ){
#line 97
  /*HplMsp430GeneralIOC.P32*/HplMsp430GeneralIOP__18__IO__selectIOFunc();
#line 97
}
#line 97
# 106 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P33*/HplMsp430GeneralIOP__19__IO__selectIOFunc(void )
#line 106
{
  /* atomic removed: atomic calls only */
#line 106
  * (volatile uint8_t * )27U &= ~(0x01 << 3);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void HplMsp430Usart0P__UCLK__selectIOFunc(void ){
#line 97
  /*HplMsp430GeneralIOC.P33*/HplMsp430GeneralIOP__19__IO__selectIOFunc();
#line 97
}
#line 97
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

# 180 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__default__granted(uint8_t id)
#line 180
{
}

# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__granted(uint8_t arg_0x7f2557c8f770){
#line 102
  switch (arg_0x7f2557c8f770) {
#line 102
    case /*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID:
#line 102
      CC2420SpiP__SpiResource__granted();
#line 102
      break;
#line 102
    default:
#line 102
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__default__granted(arg_0x7f2557c8f770);
#line 102
      break;
#line 102
    }
#line 102
}
#line 102
# 130 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__granted(uint8_t id)
#line 130
{
  /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Resource__granted(id);
}

# 363 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__default__granted(uint8_t id)
#line 363
{
}

# 102 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__granted(uint8_t arg_0x7f2557ad56a0){
#line 102
  switch (arg_0x7f2557ad56a0) {
#line 102
    case /*CC2420SpiWireC.HplCC2420SpiC.SpiC.UsartC*/Msp430Usart0C__0__CLIENT_ID:
#line 102
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartResource__granted(/*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID);
#line 102
      break;
#line 102
    default:
#line 102
      /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__default__granted(arg_0x7f2557ad56a0);
#line 102
      break;
#line 102
    }
#line 102
}
#line 102
# 346 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__grantedTask__runTask(void )
#line 346
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 347
    {
      /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__reqResId;
      /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__reqResId = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__NO_RES;
      /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_BUSY;
    }
#line 351
    __nesc_atomic_end(__nesc_atomic); }



  /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceConfigure__configure(/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId);
  /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__Resource__granted(/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId);
}

# 251 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiPacket__default__sendDone(uint8_t id, uint8_t *tx_buf, uint8_t *rx_buf, uint16_t len, error_t error)
#line 251
{
}

# 88 "/home/wtiberti/WSN/tinyos/tos/interfaces/SpiPacket.nc"
inline static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiPacket__sendDone(uint8_t arg_0x7f2557c8bb50, uint8_t * txBuf, uint8_t * rxBuf, uint16_t len, error_t error){
#line 88
  switch (arg_0x7f2557c8bb50) {
#line 88
    case /*CC2420SpiWireC.HplCC2420SpiC.SpiC*/Msp430Spi0C__0__CLIENT_ID:
#line 88
      CC2420SpiP__SpiPacket__sendDone(txBuf, rxBuf, len, error);
#line 88
      break;
#line 88
    default:
#line 88
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiPacket__default__sendDone(arg_0x7f2557c8bb50, txBuf, rxBuf, len, error);
#line 88
      break;
#line 88
    }
#line 88
}
#line 88
# 244 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone(void )
#line 244
{
  /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiPacket__sendDone(/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_client, /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_tx_buf, /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_rx_buf, /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_len, 
  SUCCESS);
}

#line 227
static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone_task__runTask(void )
#line 227
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 228
    /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone();
#line 228
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
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__HplGeneralIO__set(void ){
#line 49
  /*HplMsp430GeneralIOC.P42*/HplMsp430GeneralIOP__26__IO__set();
#line 49
}
#line 49
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__set(void )
#line 48
{
#line 48
  /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__HplGeneralIO__set();
}

# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ReceiveP__CSN__set(void ){
#line 40
  /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__set();
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
# 113 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__disableEvents(void )
#line 113
{
  * (volatile uint16_t * )390U &= ~0x0010;
}

# 77 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__disableEvents(void ){
#line 77
  /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__disableEvents();
#line 77
}
#line 77
# 65 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__stop(void )
{
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__disableEvents();
}

# 73 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__stop(void ){
#line 73
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__stop();
#line 73
}
#line 73
# 102 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__stop(void )
{
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__stop();
}

# 73 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void CC2420TransmitP__BackoffTimer__stop(void ){
#line 73
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__stop();
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
# 98 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline uint8_t /*HplMsp430GeneralIOC.P10*/HplMsp430GeneralIOP__0__IO__getRaw(void )
#line 98
{
#line 98
  return * (volatile uint8_t * )32U & (0x01 << 0);
}

#line 99
static inline bool /*HplMsp430GeneralIOC.P10*/HplMsp430GeneralIOP__0__IO__get(void )
#line 99
{
#line 99
  return /*HplMsp430GeneralIOC.P10*/HplMsp430GeneralIOP__0__IO__getRaw() != 0;
}

# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static bool /*HplCC2420PinsC.FIFOPM*/Msp430GpioC__6__HplGeneralIO__get(void ){
#line 74
  unsigned char __nesc_result;
#line 74

#line 74
  __nesc_result = /*HplMsp430GeneralIOC.P10*/HplMsp430GeneralIOP__0__IO__get();
#line 74

#line 74
  return __nesc_result;
#line 74
}
#line 74
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline bool /*HplCC2420PinsC.FIFOPM*/Msp430GpioC__6__GeneralIO__get(void )
#line 51
{
#line 51
  return /*HplCC2420PinsC.FIFOPM*/Msp430GpioC__6__HplGeneralIO__get();
}

# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static bool CC2420ReceiveP__FIFOP__get(void ){
#line 43
  unsigned char __nesc_result;
#line 43

#line 43
  __nesc_result = /*HplCC2420PinsC.FIFOPM*/Msp430GpioC__6__GeneralIO__get();
#line 43

#line 43
  return __nesc_result;
#line 43
}
#line 43
# 98 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline uint8_t /*HplMsp430GeneralIOC.P13*/HplMsp430GeneralIOP__3__IO__getRaw(void )
#line 98
{
#line 98
  return * (volatile uint8_t * )32U & (0x01 << 3);
}

#line 99
static inline bool /*HplMsp430GeneralIOC.P13*/HplMsp430GeneralIOP__3__IO__get(void )
#line 99
{
#line 99
  return /*HplMsp430GeneralIOC.P13*/HplMsp430GeneralIOP__3__IO__getRaw() != 0;
}

# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static bool /*HplCC2420PinsC.FIFOM*/Msp430GpioC__5__HplGeneralIO__get(void ){
#line 74
  unsigned char __nesc_result;
#line 74

#line 74
  __nesc_result = /*HplMsp430GeneralIOC.P13*/HplMsp430GeneralIOP__3__IO__get();
#line 74

#line 74
  return __nesc_result;
#line 74
}
#line 74
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline bool /*HplCC2420PinsC.FIFOM*/Msp430GpioC__5__GeneralIO__get(void )
#line 51
{
#line 51
  return /*HplCC2420PinsC.FIFOM*/Msp430GpioC__5__HplGeneralIO__get();
}

# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static bool CC2420ReceiveP__FIFO__get(void ){
#line 43
  unsigned char __nesc_result;
#line 43

#line 43
  __nesc_result = /*HplCC2420PinsC.FIFOM*/Msp430GpioC__5__GeneralIO__get();
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
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__HplGeneralIO__clr(void ){
#line 54
  /*HplMsp430GeneralIOC.P42*/HplMsp430GeneralIOP__26__IO__clr();
#line 54
}
#line 54
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__clr(void )
#line 49
{
#line 49
  /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__HplGeneralIO__clr();
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ReceiveP__CSN__clr(void ){
#line 41
  /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__clr();
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
inline static void CC2420SpiP__Fifo__readDone(uint8_t arg_0x7f2557d946e0, uint8_t * data, uint8_t length, error_t error){
#line 71
  switch (arg_0x7f2557d946e0) {
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
      CC2420SpiP__Fifo__default__readDone(arg_0x7f2557d946e0, data, length, error);
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
inline static /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Counter__size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Counter__get(void ){
#line 64
  unsigned long __nesc_result;
#line 64

#line 64
  __nesc_result = /*Counter32khz32C.Transform*/TransformCounterC__1__Counter__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64
# 86 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__getNow(void )
{
  return /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Counter__get();
}

#line 157
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__start(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type dt)
{
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__getNow(), dt);
}

# 66 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void CC2420TransmitP__BackoffTimer__start(CC2420TransmitP__BackoffTimer__size_type dt){
#line 66
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__start(dt);
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
inline static void CC2420ActiveMessageP__RadioBackoff__requestInitialBackoff(am_id_t arg_0x7f25574f8700, message_t * msg){
#line 81
    CC2420ActiveMessageP__RadioBackoff__default__requestInitialBackoff(arg_0x7f25574f8700, msg);
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
  /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__set();
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
  /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__clr();
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
inline static void CC2420SpiP__Fifo__writeDone(uint8_t arg_0x7f2557d946e0, uint8_t * data, uint8_t length, error_t error){
#line 91
  switch (arg_0x7f2557d946e0) {
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
      CC2420SpiP__Fifo__default__writeDone(arg_0x7f2557d946e0, data, length, error);
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
inline static void CC2420ActiveMessageP__RadioBackoff__requestCongestionBackoff(am_id_t arg_0x7f25574f8700, message_t * msg){
#line 88
    CC2420ActiveMessageP__RadioBackoff__default__requestCongestionBackoff(arg_0x7f25574f8700, msg);
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
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
inline static uint16_t /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Msp430Timer__get(void ){
#line 45
  unsigned short __nesc_result;
#line 45

#line 45
  __nesc_result = /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__get();
#line 45

#line 45
  return __nesc_result;
#line 45
}
#line 45
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430CounterC.nc"
static inline uint16_t /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__get(void )
{
  return /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Msp430Timer__get();
}

# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__size_type /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__get(void ){
#line 64
  unsigned short __nesc_result;
#line 64

#line 64
  __nesc_result = /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64
# 91 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
static inline bool /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__isOverflowPending(void )
#line 91
{
  return * (volatile uint16_t * )384U & 1U;
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
inline static bool /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Msp430Timer__isOverflowPending(void ){
#line 46
  unsigned char __nesc_result;
#line 46

#line 46
  __nesc_result = /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__isOverflowPending();
#line 46

#line 46
  return __nesc_result;
#line 46
}
#line 46
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430CounterC.nc"
static inline bool /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__isOverflowPending(void )
{
  return /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Msp430Timer__isOverflowPending();
}

# 71 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static bool /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__isOverflowPending(void ){
#line 71
  unsigned char __nesc_result;
#line 71

#line 71
  __nesc_result = /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__isOverflowPending();
#line 71

#line 71
  return __nesc_result;
#line 71
}
#line 71
# 109 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__enableEvents(void )
#line 109
{
  * (volatile uint16_t * )390U |= 0x0010;
}

# 76 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__enableEvents(void ){
#line 76
  /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__enableEvents();
#line 76
}
#line 76
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__clearPendingInterrupt(void )
#line 92
{
  * (volatile uint16_t * )390U &= ~0x0001;
}

# 43 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__clearPendingInterrupt(void ){
#line 43
  /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__clearPendingInterrupt();
#line 43
}
#line 43
# 140 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Compare__setEvent(uint16_t x)
#line 140
{
  * (volatile uint16_t * )406U = x;
}

# 42 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Compare__setEvent(uint16_t time){
#line 42
  /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Compare__setEvent(time);
#line 42
}
#line 42
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
inline static uint16_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Timer__get(void ){
#line 45
  unsigned short __nesc_result;
#line 45

#line 45
  __nesc_result = /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__get();
#line 45

#line 45
  return __nesc_result;
#line 45
}
#line 45
# 148 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Compare__setEventFromNow(uint16_t delta)
#line 148
{
  * (volatile uint16_t * )406U = /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Timer__get() + delta;
}

# 44 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Compare__setEventFromNow(uint16_t delta){
#line 44
  /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Compare__setEventFromNow(delta);
#line 44
}
#line 44
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
inline static uint16_t /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Timer__get(void ){
#line 45
  unsigned short __nesc_result;
#line 45

#line 45
  __nesc_result = /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__get();
#line 45

#line 45
  return __nesc_result;
#line 45
}
#line 45
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__startAt(uint16_t t0, uint16_t dt)
{
  /* atomic removed: atomic calls only */
  {
    uint16_t now = /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Timer__get();
    uint16_t elapsed = now - t0;

#line 87
    if (elapsed >= dt) 
      {
        /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Compare__setEventFromNow(2);
      }
    else 
      {
        uint16_t remaining = dt - elapsed;

#line 94
        if (remaining <= 2) {
          /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Compare__setEventFromNow(2);
          }
        else {
#line 97
          /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Compare__setEvent(now + remaining);
          }
      }
#line 99
    /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__clearPendingInterrupt();
    /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__enableEvents();
  }
}

# 103 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__size_type t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__size_type dt){
#line 103
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__startAt(t0, dt);
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
# 119 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port14__enable(void )
#line 119
{
#line 119
  P1IE |= 1 << 4;
}

# 44 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__enable(void ){
#line 44
  HplMsp430InterruptP__Port14__enable();
#line 44
}
#line 44
# 155 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port14__edgeRising(void )
#line 155
{
#line 155
  P1IES &= 0xef;
}

# 66 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__edgeRising(void ){
#line 66
  HplMsp430InterruptP__Port14__edgeRising();
#line 66
}
#line 66
# 137 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port14__clear(void )
#line 137
{
#line 137
  P1IFG &= ~(1 << 4);
}

# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__clear(void ){
#line 54
  HplMsp430InterruptP__Port14__clear();
#line 54
}
#line 54
# 128 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port14__disable(void )
#line 128
{
#line 128
  P1IE &= ~(1 << 4);
}

# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__disable(void ){
#line 49
  HplMsp430InterruptP__Port14__disable();
#line 49
}
#line 49
# 76 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/Msp430InterruptC.nc"
static inline error_t /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__Interrupt__disable(void )
#line 76
{
  /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__disable();
#line 90
  return SUCCESS;
}

#line 56
static inline error_t /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__Interrupt__enableRisingEdge(void )
#line 56
{
  /* atomic removed: atomic calls only */
#line 57
  {
    /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__Interrupt__disable();
    /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__clear();
    /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__edgeRising();
    /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__enable();
  }
  return SUCCESS;
}

# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
inline static error_t CC2420ControlP__InterruptCCA__enableRisingEdge(void ){
#line 53
  enum __nesc_unnamed4242 __nesc_result;
#line 53

#line 53
  __nesc_result = /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__Interrupt__enableRisingEdge();
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
  /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__clr();
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
  /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__set();
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
inline static void CC2420SpiP__Resource__granted(uint8_t arg_0x7f2557d95360){
#line 102
  switch (arg_0x7f2557d95360) {
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
      CC2420SpiP__Resource__default__granted(arg_0x7f2557d95360);
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
inline static void CC2420ActiveMessageP__AMSend__sendDone(am_id_t arg_0x7f2557501cf0, message_t * msg, error_t error){
#line 110
  /*AMQueueP.AMQueueImplP*/AMQueueImplP__0__AMSend__sendDone(arg_0x7f2557501cf0, msg, error);
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
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__HplGeneralIO__set(void ){
#line 49
  /*HplMsp430GeneralIOC.P46*/HplMsp430GeneralIOP__30__IO__set();
#line 49
}
#line 49
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__GeneralIO__set(void )
#line 48
{
#line 48
  /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__HplGeneralIO__set();
}

# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__RSTN__set(void ){
#line 40
  /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__GeneralIO__set();
#line 40
}
#line 40
# 96 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P45*/HplMsp430GeneralIOP__29__IO__clr(void )
#line 96
{
#line 96
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 96
    * (volatile uint8_t * )29U &= ~(0x01 << 5);
#line 96
    __nesc_atomic_end(__nesc_atomic); }
}

# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__HplGeneralIO__clr(void ){
#line 54
  /*HplMsp430GeneralIOC.P45*/HplMsp430GeneralIOP__29__IO__clr();
#line 54
}
#line 54
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__GeneralIO__clr(void )
#line 49
{
#line 49
  /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__HplGeneralIO__clr();
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__VREN__clr(void ){
#line 41
  /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__GeneralIO__clr();
#line 41
}
#line 41
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__HplGeneralIO__clr(void ){
#line 54
  /*HplMsp430GeneralIOC.P46*/HplMsp430GeneralIOP__30__IO__clr();
#line 54
}
#line 54
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__GeneralIO__clr(void )
#line 49
{
#line 49
  /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__HplGeneralIO__clr();
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__RSTN__clr(void ){
#line 41
  /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__GeneralIO__clr();
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
# 77 "/home/wtiberti/WSN/tinyos/tos/types/TinyError.h"
static inline  error_t ecombine(error_t r1, error_t r2)
#line 77
{
  return r1 == r2 ? r1 : FAIL;
}

# 124 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port10__disable(void )
#line 124
{
#line 124
  P1IE &= ~(1 << 0);
}

# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__disable(void ){
#line 49
  HplMsp430InterruptP__Port10__disable();
#line 49
}
#line 49
# 76 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/Msp430InterruptC.nc"
static inline error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__Interrupt__disable(void )
#line 76
{
  /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__disable();
#line 90
  return SUCCESS;
}

# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
inline static error_t CC2420ReceiveP__InterruptFIFOP__disable(void ){
#line 61
  enum __nesc_unnamed4242 __nesc_result;
#line 61

#line 61
  __nesc_result = /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__Interrupt__disable();
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

# 106 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__selectIOFunc(void )
#line 106
{
  /* atomic removed: atomic calls only */
#line 106
  * (volatile uint8_t * )31U &= ~(0x01 << 1);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__GeneralIO__selectIOFunc(void ){
#line 97
  /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__selectIOFunc();
#line 97
}
#line 97
# 113 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__disableEvents(void )
#line 113
{
  * (volatile uint16_t * )388U &= ~0x0010;
}

# 77 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__disableEvents(void ){
#line 77
  /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__disableEvents();
#line 77
}
#line 77
# 82 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/GpioCaptureC.nc"
static inline void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__disable(void )
#line 82
{
  /* atomic removed: atomic calls only */
#line 83
  {
    /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__disableEvents();
    /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__GeneralIO__selectIOFunc();
  }
}

# 66 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
inline static void CC2420TransmitP__CaptureSFD__disable(void ){
#line 66
  /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__disable();
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
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Counter__size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Counter__get(void ){
#line 64
  unsigned long __nesc_result;
#line 64

#line 64
  __nesc_result = /*CounterMilli32C.Transform*/TransformCounterC__0__Counter__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64
# 86 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__getNow(void )
{
  return /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Counter__get();
}

# 109 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__size_type /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__getNow(void ){
#line 109
  unsigned long __nesc_result;
#line 109

#line 109
  __nesc_result = /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__getNow();
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
# 115 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port10__enable(void )
#line 115
{
#line 115
  P1IE |= 1 << 0;
}

# 44 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__enable(void ){
#line 44
  HplMsp430InterruptP__Port10__enable();
#line 44
}
#line 44
# 160 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port10__edgeFalling(void )
#line 160
{
#line 160
  P1IES |= 0x01;
}

# 67 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__edgeFalling(void ){
#line 67
  HplMsp430InterruptP__Port10__edgeFalling();
#line 67
}
#line 67
# 133 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port10__clear(void )
#line 133
{
#line 133
  P1IFG &= ~(1 << 0);
}

# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__clear(void ){
#line 54
  HplMsp430InterruptP__Port10__clear();
#line 54
}
#line 54
# 66 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/Msp430InterruptC.nc"
static inline error_t /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__Interrupt__enableFallingEdge(void )
#line 66
{
  /* atomic removed: atomic calls only */
#line 67
  {
    /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__Interrupt__disable();
    /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__clear();
    /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__edgeFalling();
    /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__enable();
  }
  return SUCCESS;
}

# 54 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
inline static error_t CC2420ReceiveP__InterruptFIFOP__enableFallingEdge(void ){
#line 54
  enum __nesc_unnamed4242 __nesc_result;
#line 54

#line 54
  __nesc_result = /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__Interrupt__enableFallingEdge();
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

# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/GpioCaptureC.nc"
static inline error_t /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__captureRisingEdge(void )
#line 74
{
  return /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__enableCapture(MSP430TIMER_CM_RISING);
}

# 53 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
inline static error_t CC2420TransmitP__CaptureSFD__captureRisingEdge(void ){
#line 53
  enum __nesc_unnamed4242 __nesc_result;
#line 53

#line 53
  __nesc_result = /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__captureRisingEdge();
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

# 100 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__makeInput(void )
#line 100
{
  /* atomic removed: atomic calls only */
#line 100
  * (volatile uint8_t * )30U &= ~(0x01 << 1);
}

# 79 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__GeneralIO__makeInput(void ){
#line 79
  /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__makeInput();
#line 79
}
#line 79
# 104 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__selectModuleFunc(void )
#line 104
{
  /* atomic removed: atomic calls only */
#line 104
  * (volatile uint8_t * )31U |= 0x01 << 1;
}

# 91 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__GeneralIO__selectModuleFunc(void ){
#line 91
  /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__selectModuleFunc();
#line 91
}
#line 91
# 58 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  uint16_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__CC2int(/*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__cc_t x)
#line 58
{
#line 58
  union /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4____nesc_unnamed4368 {
#line 58
    /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__cc_t f;
#line 58
    uint16_t t;
  } 
#line 58
  c = { .f = x };

#line 58
  return c.t;
}

#line 72
static inline uint16_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__capComControl(uint8_t l_cm, uint8_t ccis, uint8_t cap_val)
#line 72
{
  /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__cc_t x = { 
  .cm = l_cm & 0x03, 
  .ccis = ccis & 0x3, 
  .clld = 0, 
  .cap = cap_val & 1, 
  .scs = 0, 
  .ccie = 0 };

  return /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__CC2int(x);
}

#line 105
static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__setControlAsCapture(uint8_t cm, uint8_t ccis)
#line 105
{
  * (volatile uint16_t * )388U = /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__capComControl(cm, ccis, 1);
}

# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__setControlAsCapture(uint8_t cm, uint8_t ccis){
#line 74
  /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__setControlAsCapture(cm, ccis);
#line 74
}
#line 74
# 109 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__enableEvents(void )
#line 109
{
  * (volatile uint16_t * )388U |= 0x0010;
}

# 76 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__enableEvents(void ){
#line 76
  /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__enableEvents();
#line 76
}
#line 76
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__size_type /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__get(void ){
#line 64
  unsigned short __nesc_result;
#line 64

#line 64
  __nesc_result = /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64







inline static bool /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__isOverflowPending(void ){
#line 71
  unsigned char __nesc_result;
#line 71

#line 71
  __nesc_result = /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__isOverflowPending();
#line 71

#line 71
  return __nesc_result;
#line 71
}
#line 71
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
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__start(dt);
#line 66
}
#line 66
# 95 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P45*/HplMsp430GeneralIOP__29__IO__set(void )
#line 95
{
#line 95
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 95
    * (volatile uint8_t * )29U |= 0x01 << 5;
#line 95
    __nesc_atomic_end(__nesc_atomic); }
}

# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__HplGeneralIO__set(void ){
#line 49
  /*HplMsp430GeneralIOC.P45*/HplMsp430GeneralIOP__29__IO__set();
#line 49
}
#line 49
# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__GeneralIO__set(void )
#line 48
{
#line 48
  /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__HplGeneralIO__set();
}

# 40 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__VREN__set(void ){
#line 40
  /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__GeneralIO__set();
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
  /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__startAt(t0, dt);
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
# 113 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__disableEvents(void )
#line 113
{
  * (volatile uint16_t * )386U &= ~0x0010;
}

# 77 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__disableEvents(void ){
#line 77
  /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__disableEvents();
#line 77
}
#line 77
# 65 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__stop(void )
{
  /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__disableEvents();
}

# 73 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__stop(void ){
#line 73
  /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__stop();
#line 73
}
#line 73
# 102 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__stop(void )
{
  /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__stop();
}

# 73 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__stop(void ){
#line 73
  /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__stop();
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

# 20 "/home/wtiberti/WSN/tinyos/tos/platforms/telosa/PlatformP.nc"
static inline uint32_t PlatformP__Platform__usecsRaw(void )
#line 20
{
#line 20
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

# 64 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
static inline uint16_t /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Timer__get(void )
{




  if (0) {
      /* atomic removed: atomic calls only */
#line 71
      {
        uint16_t t0;
        uint16_t t1 = * (volatile uint16_t * )368U;

#line 74
        do {
#line 74
            t0 = t1;
#line 74
            t1 = * (volatile uint16_t * )368U;
          }
        while (
#line 74
        t0 != t1);
        {
          unsigned short __nesc_temp = 
#line 75
          t1;

#line 75
          return __nesc_temp;
        }
      }
    }
  else 
#line 78
    {
      return * (volatile uint16_t * )368U;
    }
}

# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
inline static uint16_t /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Msp430Timer__get(void ){
#line 45
  unsigned short __nesc_result;
#line 45

#line 45
  __nesc_result = /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Timer__get();
#line 45

#line 45
  return __nesc_result;
#line 45
}
#line 45
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430CounterC.nc"
static inline uint16_t /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Counter__get(void )
{
  return /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Msp430Timer__get();
}

# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static Msp430HybridAlarmCounterP__CounterMicro__size_type Msp430HybridAlarmCounterP__CounterMicro__get(void ){
#line 64
  unsigned short __nesc_result;
#line 64

#line 64
  __nesc_result = /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Counter__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64
# 57 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430HybridAlarmCounterP.nc"
static __inline uint16_t Msp430HybridAlarmCounterP__nowMicro(void )
#line 57
{
  return Msp430HybridAlarmCounterP__CounterMicro__get();
}

# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static Msp430HybridAlarmCounterP__Counter32khz__size_type Msp430HybridAlarmCounterP__Counter32khz__get(void ){
#line 64
  unsigned short __nesc_result;
#line 64

#line 64
  __nesc_result = /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430HybridAlarmCounterP.nc"
static __inline uint16_t Msp430HybridAlarmCounterP__now32khz(void )
#line 53
{
  return Msp430HybridAlarmCounterP__Counter32khz__get();
}






static __inline void Msp430HybridAlarmCounterP__now(uint16_t *t32khz, uint16_t *tMicro, uint32_t *t2ghz)
#line 62
{
  uint16_t eMicro;

  /* atomic removed: atomic calls only */
#line 65
  {

    *t32khz = Msp430HybridAlarmCounterP__now32khz();


    *tMicro = Msp430HybridAlarmCounterP__nowMicro();


    while (*t32khz == Msp430HybridAlarmCounterP__now32khz()) ;
  }


  eMicro = Msp430HybridAlarmCounterP__nowMicro() - *tMicro;


  *t2ghz = (uint32_t )*t32khz << 16;


  *t2ghz -= (uint32_t )eMicro << 11;
}

static __inline uint32_t Msp430HybridAlarmCounterP__now2ghz(void )
#line 86
{
  uint16_t t32khz;
#line 87
  uint16_t tMicro;
  uint32_t t2ghz;

  Msp430HybridAlarmCounterP__now(&t32khz, &tMicro, &t2ghz);

  return t2ghz;
}







static inline uint32_t Msp430HybridAlarmCounterP__Counter2ghz__get(void )
#line 101
{
  return Msp430HybridAlarmCounterP__now2ghz();
}

# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__size_type /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__get(void ){
#line 64
  unsigned long __nesc_result;
#line 64

#line 64
  __nesc_result = Msp430HybridAlarmCounterP__Counter2ghz__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64







inline static bool Msp430HybridAlarmCounterP__Counter32khz__isOverflowPending(void ){
#line 71
  unsigned char __nesc_result;
#line 71

#line 71
  __nesc_result = /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__isOverflowPending();
#line 71

#line 71
  return __nesc_result;
#line 71
}
#line 71
# 110 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430HybridAlarmCounterP.nc"
static inline bool Msp430HybridAlarmCounterP__Counter2ghz__isOverflowPending(void )
#line 110
{
  return Msp430HybridAlarmCounterP__Counter32khz__isOverflowPending();
}

# 71 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static bool /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__isOverflowPending(void ){
#line 71
  unsigned char __nesc_result;
#line 71

#line 71
  __nesc_result = Msp430HybridAlarmCounterP__Counter2ghz__isOverflowPending();
#line 71

#line 71
  return __nesc_result;
#line 71
}
#line 71
# 80 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
static inline /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__to_size_type /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__Counter__get(void )
{
  /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__to_size_type rv = 0;

#line 83
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__upper_count_type high = /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__m_upper;
      /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__from_size_type low = /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__get();

#line 87
      if (/*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__isOverflowPending()) 
        {






          high++;
          low = /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__get();
        }
      {
        /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__to_size_type high_to = high;
        /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__to_size_type low_to = low >> /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__LOW_SHIFT_RIGHT;

#line 101
        rv = (high_to << /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__HIGH_SHIFT_LEFT) | low_to;
      }
    }
#line 103
    __nesc_atomic_end(__nesc_atomic); }
  return rv;
}

# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__size_type /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__get(void ){
#line 64
  unsigned long __nesc_result;
#line 64

#line 64
  __nesc_result = /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__Counter__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64
# 53 "/home/wtiberti/WSN/tinyos/tos/lib/timer/CounterToLocalTimeC.nc"
static inline uint32_t /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__LocalTime__get(void )
{
  return /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__get();
}

# 61 "/home/wtiberti/WSN/tinyos/tos/lib/timer/LocalTime.nc"
inline static uint32_t TAKSM__LocalTime__get(void ){
#line 61
  unsigned long __nesc_result;
#line 61

#line 61
  __nesc_result = /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__LocalTime__get();
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
inline static void /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__fired(uint8_t arg_0x7f2558216ca0){
#line 83
  switch (arg_0x7f2558216ca0) {
#line 83
    case 0U:
#line 83
      BlinkToRadioC__Timer0__fired();
#line 83
      break;
#line 83
    default:
#line 83
      /*HilTimerMilliC.VirtualizeTimerC.VT*/VirtualizeTimerImplP__0__Timer__default__fired(arg_0x7f2558216ca0);
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

# 109 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__enableEvents(void )
#line 109
{
  * (volatile uint16_t * )386U |= 0x0010;
}

# 76 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__enableEvents(void ){
#line 76
  /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__enableEvents();
#line 76
}
#line 76
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__clearPendingInterrupt(void )
#line 92
{
  * (volatile uint16_t * )386U &= ~0x0001;
}

# 43 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__clearPendingInterrupt(void ){
#line 43
  /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__clearPendingInterrupt();
#line 43
}
#line 43
# 140 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Compare__setEvent(uint16_t x)
#line 140
{
  * (volatile uint16_t * )402U = x;
}

# 42 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Compare__setEvent(uint16_t time){
#line 42
  /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Compare__setEvent(time);
#line 42
}
#line 42
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
inline static uint16_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Timer__get(void ){
#line 45
  unsigned short __nesc_result;
#line 45

#line 45
  __nesc_result = /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__get();
#line 45

#line 45
  return __nesc_result;
#line 45
}
#line 45
# 148 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Compare__setEventFromNow(uint16_t delta)
#line 148
{
  * (volatile uint16_t * )402U = /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Timer__get() + delta;
}

# 44 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Compare__setEventFromNow(uint16_t delta){
#line 44
  /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Compare__setEventFromNow(delta);
#line 44
}
#line 44
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
inline static uint16_t /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Timer__get(void ){
#line 45
  unsigned short __nesc_result;
#line 45

#line 45
  __nesc_result = /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__get();
#line 45

#line 45
  return __nesc_result;
#line 45
}
#line 45
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__startAt(uint16_t t0, uint16_t dt)
{
  /* atomic removed: atomic calls only */
  {
    uint16_t now = /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Timer__get();
    uint16_t elapsed = now - t0;

#line 87
    if (elapsed >= dt) 
      {
        /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Compare__setEventFromNow(2);
      }
    else 
      {
        uint16_t remaining = dt - elapsed;

#line 94
        if (remaining <= 2) {
          /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Compare__setEventFromNow(2);
          }
        else {
#line 97
          /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Compare__setEvent(now + remaining);
          }
      }
#line 99
    /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__clearPendingInterrupt();
    /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__enableEvents();
  }
}

# 103 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__startAt(/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__size_type t0, /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__size_type dt){
#line 103
  /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__startAt(t0, dt);
#line 103
}
#line 103
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
# 91 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__getAlarm(void )
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 93
    {
      /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type __nesc_temp = 
#line 93
      /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_t0 + /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_dt;

      {
#line 93
        __nesc_atomic_end(__nesc_atomic); 
#line 93
        return __nesc_temp;
      }
    }
#line 95
    __nesc_atomic_end(__nesc_atomic); }
}

# 116 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__size_type /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__getAlarm(void ){
#line 116
  unsigned long __nesc_result;
#line 116

#line 116
  __nesc_result = /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__getAlarm();
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

# 58 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  uint16_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__CC2int(/*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__cc_t x)
#line 58
{
#line 58
  union /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3____nesc_unnamed4369 {
#line 58
    /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__cc_t f;
#line 58
    uint16_t t;
  } 
#line 58
  c = { .f = x };

#line 58
  return c.t;
}

#line 72
static inline uint16_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__capComControl(uint8_t l_cm, uint8_t ccis, uint8_t cap_val)
#line 72
{
  /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__cc_t x = { 
  .cm = l_cm & 0x03, 
  .ccis = ccis & 0x3, 
  .clld = 0, 
  .cap = cap_val & 1, 
  .scs = 0, 
  .ccie = 0 };

  return /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__CC2int(x);
}

#line 100
static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__setControlAsCompare(void )
#line 100
{

  * (volatile uint16_t * )386U = /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__capComControl(MSP430TIMER_CM_RISING, MSP430TIMER_CCI_A, 0);
}

# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__setControlAsCompare(void ){
#line 56
  /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__setControlAsCompare();
#line 56
}
#line 56
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline error_t /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Init__init(void )
{
  /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__disableEvents();
  /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__setControlAsCompare();
  return SUCCESS;
}

# 48 "/home/wtiberti/WSN/tinyos/tos/interfaces/LocalIeeeEui64.nc"
inline static ieee_eui64_t CC2420ControlP__LocalIeeeEui64__getId(void ){
#line 48
  struct ieee_eui64 __nesc_result;
#line 48

#line 48
  __nesc_result = LocalIeeeEui64P__LocalIeeeEui64__getId();
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
# 102 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P45*/HplMsp430GeneralIOP__29__IO__makeOutput(void )
#line 102
{
  /* atomic removed: atomic calls only */
#line 102
  * (volatile uint8_t * )30U |= 0x01 << 5;
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__HplGeneralIO__makeOutput(void ){
#line 85
  /*HplMsp430GeneralIOC.P45*/HplMsp430GeneralIOP__29__IO__makeOutput();
#line 85
}
#line 85
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__GeneralIO__makeOutput(void )
#line 54
{
#line 54
  /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__HplGeneralIO__makeOutput();
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__VREN__makeOutput(void ){
#line 46
  /*HplCC2420PinsC.VRENM*/Msp430GpioC__9__GeneralIO__makeOutput();
#line 46
}
#line 46
# 102 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P46*/HplMsp430GeneralIOP__30__IO__makeOutput(void )
#line 102
{
  /* atomic removed: atomic calls only */
#line 102
  * (volatile uint8_t * )30U |= 0x01 << 6;
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__HplGeneralIO__makeOutput(void ){
#line 85
  /*HplMsp430GeneralIOC.P46*/HplMsp430GeneralIOP__30__IO__makeOutput();
#line 85
}
#line 85
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__GeneralIO__makeOutput(void )
#line 54
{
#line 54
  /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__HplGeneralIO__makeOutput();
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__RSTN__makeOutput(void ){
#line 46
  /*HplCC2420PinsC.RSTNM*/Msp430GpioC__7__GeneralIO__makeOutput();
#line 46
}
#line 46
# 102 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P42*/HplMsp430GeneralIOP__26__IO__makeOutput(void )
#line 102
{
  /* atomic removed: atomic calls only */
#line 102
  * (volatile uint8_t * )30U |= 0x01 << 2;
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__HplGeneralIO__makeOutput(void ){
#line 85
  /*HplMsp430GeneralIOC.P42*/HplMsp430GeneralIOP__26__IO__makeOutput();
#line 85
}
#line 85
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__makeOutput(void )
#line 54
{
#line 54
  /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__HplGeneralIO__makeOutput();
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420ControlP__CSN__makeOutput(void ){
#line 46
  /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__makeOutput();
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
static inline error_t /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__Init__init(void )
#line 55
{
  memset(/*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__resQ, /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__NO_ENTRY, sizeof /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__resQ);
  return SUCCESS;
}

# 58 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  uint16_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__CC2int(/*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__cc_t x)
#line 58
{
#line 58
  union /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5____nesc_unnamed4370 {
#line 58
    /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__cc_t f;
#line 58
    uint16_t t;
  } 
#line 58
  c = { .f = x };

#line 58
  return c.t;
}

#line 72
static inline uint16_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__capComControl(uint8_t l_cm, uint8_t ccis, uint8_t cap_val)
#line 72
{
  /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__cc_t x = { 
  .cm = l_cm & 0x03, 
  .ccis = ccis & 0x3, 
  .clld = 0, 
  .cap = cap_val & 1, 
  .scs = 0, 
  .ccie = 0 };

  return /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__CC2int(x);
}

#line 100
static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__setControlAsCompare(void )
#line 100
{

  * (volatile uint16_t * )390U = /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__capComControl(MSP430TIMER_CM_RISING, MSP430TIMER_CCI_A, 0);
}

# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__setControlAsCompare(void ){
#line 56
  /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__setControlAsCompare();
#line 56
}
#line 56
# 53 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline error_t /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Init__init(void )
{
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__disableEvents();
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__setControlAsCompare();
  return SUCCESS;
}

# 79 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__HplGeneralIO__makeInput(void ){
#line 79
  /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__makeInput();
#line 79
}
#line 79
# 52 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__GeneralIO__makeInput(void )
#line 52
{
#line 52
  /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__HplGeneralIO__makeInput();
}

# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420TransmitP__SFD__makeInput(void ){
#line 44
  /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__GeneralIO__makeInput();
#line 44
}
#line 44


inline static void CC2420TransmitP__CSN__makeOutput(void ){
#line 46
  /*HplCC2420PinsC.CSNM*/Msp430GpioC__4__GeneralIO__makeOutput();
#line 46
}
#line 46
# 100 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P14*/HplMsp430GeneralIOP__4__IO__makeInput(void )
#line 100
{
  /* atomic removed: atomic calls only */
#line 100
  * (volatile uint8_t * )34U &= ~(0x01 << 4);
}

# 79 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__HplGeneralIO__makeInput(void ){
#line 79
  /*HplMsp430GeneralIOC.P14*/HplMsp430GeneralIOP__4__IO__makeInput();
#line 79
}
#line 79
# 52 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__GeneralIO__makeInput(void )
#line 52
{
#line 52
  /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__HplGeneralIO__makeInput();
}

# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void CC2420TransmitP__CCA__makeInput(void ){
#line 44
  /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__GeneralIO__makeInput();
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

# 67 "/home/wtiberti/WSN/tinyos/tos/interfaces/TaskBasic.nc"
inline static error_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__grantedTask__postTask(void ){
#line 67
  enum __nesc_unnamed4242 __nesc_result;
#line 67

#line 67
  __nesc_result = SchedulerBasicP__TaskBasic__postTask(/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__grantedTask);
#line 67

#line 67
  return __nesc_result;
#line 67
}
#line 67
# 283 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline error_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwner__release(void )
#line 283
{
  /* atomic removed: atomic calls only */
#line 284
  {
    if (/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__resId == /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__default_owner_id) {
        if (/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__state == /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__RES_GRANTING || /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__state == /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__RES_PREGRANT) {
            /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__state = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__RES_GRANTING;
            /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__grantedTask__postTask();
            {
              enum __nesc_unnamed4242 __nesc_temp = 
#line 289
              SUCCESS;

#line 289
              return __nesc_temp;
            }
          }
        else {
#line 291
          if (/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__state == /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__RES_IMM_GRANTING) {
              /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__resId = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__reqResId;
              /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__reqResId = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__NO_RES;
              /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__state = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__RES_BUSY;
              {
                enum __nesc_unnamed4242 __nesc_temp = 
#line 295
                SUCCESS;

#line 295
                return __nesc_temp;
              }
            }
          }
      }
  }
#line 299
  return FAIL;
}

# 54 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwner.nc"
inline static error_t /*Msp430UsartShare1P.PowerManagerC.PowerManager*/AsyncPowerManagerP__0__ResourceDefaultOwner__release(void ){
#line 54
  enum __nesc_unnamed4242 __nesc_result;
#line 54

#line 54
  __nesc_result = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwner__release();
#line 54

#line 54
  return __nesc_result;
#line 54
}
#line 54
# 91 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
static inline error_t HplMsp430Usart1P__AsyncStdControl__start(void )
#line 91
{
  return SUCCESS;
}

# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/AsyncStdControl.nc"
inline static error_t /*Msp430UsartShare1P.PowerManagerC.PowerManager*/AsyncPowerManagerP__0__AsyncStdControl__start(void ){
#line 95
  enum __nesc_unnamed4242 __nesc_result;
#line 95

#line 95
  __nesc_result = HplMsp430Usart1P__AsyncStdControl__start();
#line 95

#line 95
  return __nesc_result;
#line 95
}
#line 95
# 74 "/home/wtiberti/WSN/tinyos/tos/lib/power/AsyncPowerManagerP.nc"
static inline void /*Msp430UsartShare1P.PowerManagerC.PowerManager*/AsyncPowerManagerP__0__ResourceDefaultOwner__immediateRequested(void )
#line 74
{
  /*Msp430UsartShare1P.PowerManagerC.PowerManager*/AsyncPowerManagerP__0__AsyncStdControl__start();
  /*Msp430UsartShare1P.PowerManagerC.PowerManager*/AsyncPowerManagerP__0__ResourceDefaultOwner__release();
}

# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwner.nc"
inline static void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwner__immediateRequested(void ){
#line 79
  /*Msp430UsartShare1P.PowerManagerC.PowerManager*/AsyncPowerManagerP__0__ResourceDefaultOwner__immediateRequested();
#line 79
}
#line 79
# 365 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceRequested__default__immediateRequested(uint8_t id)
#line 365
{
}

# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceRequested.nc"
inline static void /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceRequested__immediateRequested(uint8_t arg_0x7f2557ad49d0){
#line 61
    /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceRequested__default__immediateRequested(arg_0x7f2557ad49d0);
#line 61
}
#line 61
# 222 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline error_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__immediateRequest(uint8_t id)
#line 222
{
  /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceRequested__immediateRequested(/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__resId);
  /* atomic removed: atomic calls only */
#line 224
  {




    if (/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__state != /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__RES_DEF_OWNED) 
      {
        enum __nesc_unnamed4242 __nesc_temp = 
#line 230
        FAIL;

#line 230
        return __nesc_temp;
      }
#line 231
    /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__state = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__RES_IMM_GRANTING;
    /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__reqResId = id;
  }
  /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwner__immediateRequested();
  if (/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__resId == id) {
      /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceConfigure__configure(/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__resId);
      return SUCCESS;
    }
  /* atomic removed: atomic calls only */





  /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__state = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__RES_DEF_OWNED;
  return FAIL;
}

# 234 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline error_t /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__default__immediateRequest(uint8_t id)
#line 234
{
#line 234
  return FAIL;
}

# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__immediateRequest(uint8_t arg_0x7f2557265ca0){
#line 97
  enum __nesc_unnamed4242 __nesc_result;
#line 97

#line 97
  switch (arg_0x7f2557265ca0) {
#line 97
    case /*PlatformSerialC.UartC*/Msp430Uart1C__0__CLIENT_ID:
#line 97
      __nesc_result = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__immediateRequest(/*PlatformSerialC.UartC.UsartC*/Msp430Usart1C__0__CLIENT_ID);
#line 97
      break;
#line 97
    default:
#line 97
      __nesc_result = /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__default__immediateRequest(arg_0x7f2557265ca0);
#line 97
      break;
#line 97
    }
#line 97

#line 97
  return __nesc_result;
#line 97
}
#line 97
# 68 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline error_t /*Msp430Uart1P.UartP*/Msp430UartP__0__Resource__immediateRequest(uint8_t id)
#line 68
{
  return /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__immediateRequest(id);
}

# 97 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static error_t TelosSerialP__Resource__immediateRequest(void ){
#line 97
  enum __nesc_unnamed4242 __nesc_result;
#line 97

#line 97
  __nesc_result = /*Msp430Uart1P.UartP*/Msp430UartP__0__Resource__immediateRequest(/*PlatformSerialC.UartC*/Msp430Uart1C__0__CLIENT_ID);
#line 97

#line 97
  return __nesc_result;
#line 97
}
#line 97
# 15 "/home/wtiberti/WSN/tinyos/tos/platforms/telosa/TelosSerialP.nc"
static inline error_t TelosSerialP__StdControl__start(void )
#line 15
{
  return TelosSerialP__Resource__immediateRequest();
}

# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
inline static error_t SerialPrintfP__UartControl__start(void ){
#line 95
  enum __nesc_unnamed4242 __nesc_result;
#line 95

#line 95
  __nesc_result = TelosSerialP__StdControl__start();
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

# 55 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
static inline error_t /*Msp430UsartShare1P.ArbiterC.Queue*/FcfsResourceQueueC__2__Init__init(void )
#line 55
{
  memset(/*Msp430UsartShare1P.ArbiterC.Queue*/FcfsResourceQueueC__2__resQ, /*Msp430UsartShare1P.ArbiterC.Queue*/FcfsResourceQueueC__2__NO_ENTRY, sizeof /*Msp430UsartShare1P.ArbiterC.Queue*/FcfsResourceQueueC__2__resQ);
  return SUCCESS;
}

# 98 "/home/wtiberti/WSN/tinyos/tos/lib/printf/PutcharP.nc"
static inline error_t PutcharP__Init__init(void )
#line 98
{
  error_t rv = SUCCESS;



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
  __nesc_result = ecombine(__nesc_result, /*Msp430UsartShare1P.ArbiterC.Queue*/FcfsResourceQueueC__2__Init__init());
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
  __nesc_result = ecombine(__nesc_result, /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, StateImplP__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, CC2420ControlP__Init__init());
#line 62
  __nesc_result = ecombine(__nesc_result, /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Init__init());
#line 62

#line 62
  return __nesc_result;
#line 62
}
#line 62
# 24 "/home/wtiberti/WSN/tinyos/tos/chips/ds2411/Ds2411P.nc"
static inline bool Ds2411P__ds2411_check_crc(const ds2411_serial_t *id)
#line 24
{
  uint8_t crc = 0;
  uint8_t idx;

#line 27
  for (idx = 0; idx < DS2411_DATA_LENGTH; idx++) {
      uint8_t i;

#line 29
      crc = crc ^ id->data[idx];
      for (i = 0; i < 8; i++) {
          if (crc & 0x01) {
              crc = (crc >> 1) ^ 0x8C;
            }
          else 
#line 33
            {
              crc >>= 1;
            }
        }
    }
  return crc == 0;
}

# 23 "/home/wtiberti/WSN/tinyos/tos/chips/ds2411/Ds2411PowerControlC.nc"
static inline error_t Ds2411PowerControlC__StdControl__stop(void )
#line 23
{
  return SUCCESS;
}

# 105 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
inline static error_t Ds2411P__PowerControl__stop(void ){
#line 105
  enum __nesc_unnamed4242 __nesc_result;
#line 105

#line 105
  __nesc_result = Ds2411PowerControlC__StdControl__stop();
#line 105

#line 105
  return __nesc_result;
#line 105
}
#line 105
# 66 "/home/wtiberti/WSN/tinyos/tos/lib/timer/BusyWait.nc"
inline static void OneWireMasterP__BusyWait__wait(OneWireMasterP__BusyWait__size_type dt){
#line 66
  /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__BusyWait__wait(dt);
#line 66
}
#line 66
# 98 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline uint8_t /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__getRaw(void )
#line 98
{
#line 98
  return * (volatile uint8_t * )40U & (0x01 << 4);
}

#line 99
static inline bool /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__get(void )
#line 99
{
#line 99
  return /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__getRaw() != 0;
}

# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static bool /*HplDs2411C.MspGpio*/Msp430GpioC__10__HplGeneralIO__get(void ){
#line 74
  unsigned char __nesc_result;
#line 74

#line 74
  __nesc_result = /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__get();
#line 74

#line 74
  return __nesc_result;
#line 74
}
#line 74
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline bool /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__get(void )
#line 51
{
#line 51
  return /*HplDs2411C.MspGpio*/Msp430GpioC__10__HplGeneralIO__get();
}

# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static bool OneWireMasterP__Pin__get(void ){
#line 43
  unsigned char __nesc_result;
#line 43

#line 43
  __nesc_result = /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__get();
#line 43

#line 43
  return __nesc_result;
#line 43
}
#line 43
# 100 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__makeInput(void )
#line 100
{
  /* atomic removed: atomic calls only */
#line 100
  * (volatile uint8_t * )42U &= ~(0x01 << 4);
}

# 79 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplDs2411C.MspGpio*/Msp430GpioC__10__HplGeneralIO__makeInput(void ){
#line 79
  /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__makeInput();
#line 79
}
#line 79
# 52 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__makeInput(void )
#line 52
{
#line 52
  /*HplDs2411C.MspGpio*/Msp430GpioC__10__HplGeneralIO__makeInput();
}

# 44 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void OneWireMasterP__Pin__makeInput(void ){
#line 44
  /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__makeInput();
#line 44
}
#line 44
# 102 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__makeOutput(void )
#line 102
{
  /* atomic removed: atomic calls only */
#line 102
  * (volatile uint8_t * )42U |= 0x01 << 4;
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplDs2411C.MspGpio*/Msp430GpioC__10__HplGeneralIO__makeOutput(void ){
#line 85
  /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__makeOutput();
#line 85
}
#line 85
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__makeOutput(void )
#line 54
{
#line 54
  /*HplDs2411C.MspGpio*/Msp430GpioC__10__HplGeneralIO__makeOutput();
}

# 46 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void OneWireMasterP__Pin__makeOutput(void ){
#line 46
  /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__makeOutput();
#line 46
}
#line 46
# 66 "/home/wtiberti/WSN/tinyos/tos/lib/onewire/OneWireMasterP.nc"
static inline bool OneWireMasterP__readBit(void )
#line 66
{
  bool bit;

#line 68
  OneWireMasterP__Pin__makeOutput();
  OneWireMasterP__BusyWait__wait(OneWireMasterP__DELAY_5US);
  OneWireMasterP__Pin__makeInput();
  OneWireMasterP__BusyWait__wait(OneWireMasterP__DELAY_5US);
  bit = OneWireMasterP__Pin__get();
  OneWireMasterP__BusyWait__wait(OneWireMasterP__SLOT_TIME);
  return bit;
}

#line 89
static inline uint8_t OneWireMasterP__readByte(void )
#line 89
{
  uint8_t i;
#line 90
  uint8_t c = 0;

#line 91
  for (i = 0; i < 8; i++) {
      c >>= 1;
      if (OneWireMasterP__readBit()) {
          c |= 0x80;
        }
    }
  return c;
}

#line 59
static inline void OneWireMasterP__writeZero(void )
#line 59
{
  OneWireMasterP__Pin__makeOutput();
  OneWireMasterP__BusyWait__wait(OneWireMasterP__DELAY_60US);
  OneWireMasterP__Pin__makeInput();
  OneWireMasterP__BusyWait__wait(OneWireMasterP__DELAY_5US);
}

#line 52
static inline void OneWireMasterP__writeOne(void )
#line 52
{
  OneWireMasterP__Pin__makeOutput();
  OneWireMasterP__BusyWait__wait(OneWireMasterP__DELAY_5US);
  OneWireMasterP__Pin__makeInput();
  OneWireMasterP__BusyWait__wait(OneWireMasterP__SLOT_TIME);
}

#line 77
static inline void OneWireMasterP__writeByte(uint8_t c)
#line 77
{
  uint8_t j;

#line 79
  for (j = 0; j < 8; j++) {
      if (c & 0x01) {
          OneWireMasterP__writeOne();
        }
      else 
#line 82
        {
          OneWireMasterP__writeZero();
        }
      c >>= 1;
    }
}

# 96 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline void /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__clr(void )
#line 96
{
  /* atomic removed: atomic calls only */
#line 96
  * (volatile uint8_t * )41U &= ~(0x01 << 4);
}

# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static void /*HplDs2411C.MspGpio*/Msp430GpioC__10__HplGeneralIO__clr(void ){
#line 54
  /*HplMsp430GeneralIOC.P24*/HplMsp430GeneralIOP__12__IO__clr();
#line 54
}
#line 54
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline void /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__clr(void )
#line 49
{
#line 49
  /*HplDs2411C.MspGpio*/Msp430GpioC__10__HplGeneralIO__clr();
}

# 41 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static void OneWireMasterP__Pin__clr(void ){
#line 41
  /*HplDs2411C.MspGpio*/Msp430GpioC__10__GeneralIO__clr();
#line 41
}
#line 41
# 34 "/home/wtiberti/WSN/tinyos/tos/lib/onewire/OneWireMasterP.nc"
static inline bool OneWireMasterP__reset(void )
#line 34
{
  uint16_t i;

#line 36
  OneWireMasterP__Pin__makeInput();
  OneWireMasterP__Pin__clr();
  OneWireMasterP__Pin__makeOutput();
  OneWireMasterP__BusyWait__wait(OneWireMasterP__RESET_LOW_TIME);
  OneWireMasterP__Pin__makeInput();
  OneWireMasterP__BusyWait__wait(OneWireMasterP__DELAY_60US);

  for (i = 0; 
  i < OneWireMasterP__PRESENCE_DETECT_LOW_TIME; 
  i += OneWireMasterP__DELAY_5US, OneWireMasterP__BusyWait__wait(OneWireMasterP__DELAY_5US)) {
      if (!OneWireMasterP__Pin__get()) {
#line 46
        break;
        }
    }
#line 48
  OneWireMasterP__BusyWait__wait(OneWireMasterP__PRESENCE_RESET_HIGH_TIME - OneWireMasterP__DELAY_60US);
  return i < OneWireMasterP__PRESENCE_DETECT_LOW_TIME;
}

#line 100
static inline error_t OneWireMasterP__OneWire__read(uint8_t cmd, uint8_t *buf, uint8_t len)
#line 100
{
  error_t e = SUCCESS;

  /* atomic removed: atomic calls only */
#line 102
  {
    if (OneWireMasterP__reset()) {
        uint8_t i;

#line 105
        OneWireMasterP__writeByte(cmd);
        for (i = 0; i < len; i++) {
            buf[i] = OneWireMasterP__readByte();
          }
      }
    else 
#line 109
      {
        e = EOFF;
      }
  }
  return e;
}

# 10 "/home/wtiberti/WSN/tinyos/tos/lib/onewire/OneWireReadWrite.nc"
inline static error_t Ds2411P__OneWire__read(uint8_t cmd, uint8_t *buf, uint8_t len){
#line 10
  enum __nesc_unnamed4242 __nesc_result;
#line 10

#line 10
  __nesc_result = OneWireMasterP__OneWire__read(cmd, buf, len);
#line 10

#line 10
  return __nesc_result;
#line 10
}
#line 10
# 19 "/home/wtiberti/WSN/tinyos/tos/chips/ds2411/Ds2411PowerControlC.nc"
static inline error_t Ds2411PowerControlC__StdControl__start(void )
#line 19
{
  return SUCCESS;
}

# 95 "/home/wtiberti/WSN/tinyos/tos/interfaces/StdControl.nc"
inline static error_t Ds2411P__PowerControl__start(void ){
#line 95
  enum __nesc_unnamed4242 __nesc_result;
#line 95

#line 95
  __nesc_result = Ds2411PowerControlC__StdControl__start();
#line 95

#line 95
  return __nesc_result;
#line 95
}
#line 95
# 41 "/home/wtiberti/WSN/tinyos/tos/chips/ds2411/Ds2411P.nc"
static inline error_t Ds2411P__readId(void )
#line 41
{
  error_t e;

  e = Ds2411P__PowerControl__start();
  if (e != SUCCESS) {
#line 45
    return FAIL;
    }
  e = Ds2411P__OneWire__read(0x33, 
  Ds2411P__ds2411id.data, 
  DS2411_DATA_LENGTH);
  Ds2411P__PowerControl__stop();

  if (e == SUCCESS) {
      if (Ds2411P__ds2411_check_crc(&Ds2411P__ds2411id)) {
          Ds2411P__haveId = TRUE;
        }
      else 
#line 55
        {
          e = EINVAL;
        }
    }
  return e;
}

static inline error_t Ds2411P__ReadId48__read(uint8_t *id)
#line 62
{
  error_t e = SUCCESS;

#line 64
  if (!Ds2411P__haveId) {
      e = Ds2411P__readId();
    }
  if (Ds2411P__haveId) {
      memcpy(id, Ds2411P__ds2411id.serial, DS2411_SERIAL_LENGTH);
    }
  return e;
}

# 13 "/home/wtiberti/WSN/tinyos/tos/chips/ds2411/ReadId48.nc"
inline static error_t LocalIeeeEui64P__ReadId48__read(uint8_t *id){
#line 13
  enum __nesc_unnamed4242 __nesc_result;
#line 13

#line 13
  __nesc_result = Ds2411P__ReadId48__read(id);
#line 13

#line 13
  return __nesc_result;
#line 13
}
#line 13
# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__size_type /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__get(void ){
#line 64
  unsigned short __nesc_result;
#line 64

#line 64
  __nesc_result = /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Counter__get();
#line 64

#line 64
  return __nesc_result;
#line 64
}
#line 64
# 608 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/msp430hardware.h"
static __inline __attribute((always_inline))  void __nesc_enable_interrupt(void )
#line 608
{

   __asm volatile ("nop");

   __asm volatile ("eint { nop");}

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

# 598 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/msp430hardware.h"
static __inline __attribute((always_inline))  void __nesc_disable_interrupt(void )
#line 598
{

   __asm volatile ("nop");

   __asm volatile ("dint { nop");

   __asm volatile ("nop");}

#line 581
static inline  mcu_power_t mcombine(mcu_power_t m1, mcu_power_t m2)
#line 581
{
  return m1 < m2 ? m1 : m2;
}

# 228 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/clock_bcs/Msp430ClockP.nc"
static inline mcu_power_t Msp430ClockP__McuPowerOverride__lowestState(void )
#line 228
{
  return MSP430_POWER_LPM3;
}

# 117 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline bool /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__areEventsEnabled(void )
#line 117
{
  return * (volatile uint16_t * )354U & 0x0010;
}

# 78 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static bool /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430TimerControl__areEventsEnabled(void ){
#line 78
  unsigned char __nesc_result;
#line 78

#line 78
  __nesc_result = /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__areEventsEnabled();
#line 78

#line 78
  return __nesc_result;
#line 78
}
#line 78
# 76 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline bool /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__isRunning(void )
{
  return /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430TimerControl__areEventsEnabled();
}

# 88 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static bool Msp430HybridAlarmCounterP__AlarmMicro__isRunning(void ){
#line 88
  unsigned char __nesc_result;
#line 88

#line 88
  __nesc_result = /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__isRunning();
#line 88

#line 88
  return __nesc_result;
#line 88
}
#line 88
# 260 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430HybridAlarmCounterP.nc"
static inline mcu_power_t Msp430HybridAlarmCounterP__McuPowerOverride__lowestState(void )
#line 260
{
  if (Msp430HybridAlarmCounterP__AlarmMicro__isRunning()) {
    return MSP430_POWER_LPM0;
    }
  else {
#line 264
    return MSP430_POWER_LPM3;
    }
}

# 62 "/home/wtiberti/WSN/tinyos/tos/interfaces/McuPowerOverride.nc"
inline static mcu_power_t McuSleepC__McuPowerOverride__lowestState(void ){
#line 62
  unsigned char __nesc_result;
#line 62

#line 62
  __nesc_result = Msp430HybridAlarmCounterP__McuPowerOverride__lowestState();
#line 62
  __nesc_result = mcombine(__nesc_result, Msp430ClockP__McuPowerOverride__lowestState());
#line 62

#line 62
  return __nesc_result;
#line 62
}
#line 62
# 79 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1xxx/McuSleepC.nc"
static inline mcu_power_t McuSleepC__getPowerState(void )
#line 79
{
  mcu_power_t pState = MSP430_POWER_LPM4;











  if ((((((
#line 82
  TACCTL0 & 0x0010 || 
  TACCTL1 & 0x0010) || 
  TACCTL2 & 0x0010) && (
  TACTL & 0x0300) == 0x0200) || (
  ME1 & (0x80 | 0x40) && U0TCTL & 0x20)) || (
  ME2 & (0x20 | 0x10) && U1TCTL & 0x20))




   || (McuSleepC__U0CTLnr & 0x01 && McuSleepC__I2CTCTLnr & 0x20 && 
  McuSleepC__I2CDCTLnr & 0x20 && McuSleepC__U0CTLnr & 0x04 && McuSleepC__U0CTLnr & 0x20)) {


    pState = MSP430_POWER_LPM1;
    }


  if (ADC12CTL0 & 0x010) {
      if (ADC12CTL1 & 0x0010) {

          if (ADC12CTL1 & 0x0008) {
            pState = MSP430_POWER_LPM1;
            }
          else {
#line 106
            pState = MSP430_POWER_ACTIVE;
            }
        }
      else {
#line 107
        if (ADC12CTL1 & 0x0400 && (TACTL & 0x0300) == 0x0200) {



            pState = MSP430_POWER_LPM1;
          }
        }
    }

  return pState;
}

static inline void McuSleepC__computePowerState(void )
#line 119
{
  McuSleepC__powerState = mcombine(McuSleepC__getPowerState(), 
  McuSleepC__McuPowerOverride__lowestState());
}

static inline void McuSleepC__McuSleep__sleep(void )
#line 124
{
  uint16_t temp;

#line 126
  if (McuSleepC__dirty) {
      McuSleepC__computePowerState();
    }

  temp = McuSleepC__msp430PowerBits[McuSleepC__powerState] | 0x0008;
   __asm volatile ("bis  %0, r2" :  : "m"(temp));

   __asm volatile ("" :  :  : "memory");
  __nesc_disable_interrupt();
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
# 171 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Timer__overflow(void )
#line 171
{
}

#line 171
static inline void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Timer__overflow(void )
#line 171
{
}

#line 171
static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Timer__overflow(void )
#line 171
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/lib/timer/BusyWaitCounterC.nc"
static inline void /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__overflow(void )
{
}

# 128 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430HybridAlarmCounterP.nc"
static inline void Msp430HybridAlarmCounterP__CounterMicro__overflow(void )
#line 128
{
}

# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static void /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Counter__overflow(void ){
#line 82
  Msp430HybridAlarmCounterP__CounterMicro__overflow();
#line 82
  /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__overflow();
#line 82
}
#line 82
# 64 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430CounterC.nc"
static inline void /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Msp430Timer__overflow(void )
{
  /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Counter__overflow();
}

# 114 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Timer__overflow(void )
{
}

# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
inline static void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Timer__overflow(void ){
#line 48
  /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Timer__overflow();
#line 48
  /*Msp430CounterMicroC.Counter*/Msp430CounterC__1__Msp430Timer__overflow();
#line 48
  /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Timer__overflow();
#line 48
  /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Timer__overflow();
#line 48
  /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Timer__overflow();
#line 48
}
#line 48
# 162 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
static inline void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Overflow__fired(void )
{
  /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Timer__overflow();
}


static inline void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Event__default__fired(uint8_t n)
#line 168
{
}

# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
inline static void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Event__fired(uint8_t arg_0x7f25584338b0){
#line 39
  switch (arg_0x7f25584338b0) {
#line 39
    case 0:
#line 39
      /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Event__fired();
#line 39
      break;
#line 39
    case 1:
#line 39
      /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Event__fired();
#line 39
      break;
#line 39
    case 2:
#line 39
      /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Event__fired();
#line 39
      break;
#line 39
    case 5:
#line 39
      /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Overflow__fired();
#line 39
      break;
#line 39
    default:
#line 39
      /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Event__default__fired(arg_0x7f25584338b0);
#line 39
      break;
#line 39
    }
#line 39
}
#line 39
# 144 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
static inline void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__VectorTimerX0__fired(void )
#line 144
{
  /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Event__fired(0);
}

# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
inline static void Msp430TimerCommonP__VectorTimerA0__fired(void ){
#line 39
  /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__VectorTimerX0__fired();
#line 39
}
#line 39
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__cc_t /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__int2CC(uint16_t x)
#line 59
{
#line 59
  union /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0____nesc_unnamed4371 {
#line 59
    uint16_t f;
#line 59
    /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__cc_t t;
  } 
#line 59
  c = { .f = x };

#line 59
  return c.t;
}

#line 84
static inline /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__cc_t /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__getControl(void )
#line 84
{
  return /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__int2CC(* (volatile uint16_t * )354U);
}

#line 167
static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Capture__default__captured(uint16_t n)
#line 167
{
}

# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
inline static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Capture__captured(uint16_t time){
#line 92
  /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Capture__default__captured(time);
#line 92
}
#line 92
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline uint16_t /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Capture__getEvent(void )
#line 136
{
  return * (volatile uint16_t * )370U;
}

# 191 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430HybridAlarmCounterP.nc"
static inline void Msp430HybridAlarmCounterP__Alarm2ghz__default__fired(void )
#line 191
{
}

# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void Msp430HybridAlarmCounterP__Alarm2ghz__fired(void ){
#line 78
  Msp430HybridAlarmCounterP__Alarm2ghz__default__fired();
#line 78
}
#line 78
# 176 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430HybridAlarmCounterP.nc"
static inline void Msp430HybridAlarmCounterP__AlarmMicro__fired(void )
#line 176
{

  Msp430HybridAlarmCounterP__Alarm2ghz__fired();
}

# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__fired(void ){
#line 78
  Msp430HybridAlarmCounterP__AlarmMicro__fired();
#line 78
}
#line 78
# 113 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__disableEvents(void )
#line 113
{
  * (volatile uint16_t * )354U &= ~0x0010;
}

# 77 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430TimerControl__disableEvents(void ){
#line 77
  /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__disableEvents();
#line 77
}
#line 77
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Compare__fired(void )
{
  /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430TimerControl__disableEvents();
  /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__fired();
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Compare__fired(void ){
#line 46
  /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Compare__fired();
#line 46
}
#line 46
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__cc_t /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__int2CC(uint16_t x)
#line 59
{
#line 59
  union /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1____nesc_unnamed4372 {
#line 59
    uint16_t f;
#line 59
    /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__cc_t t;
  } 
#line 59
  c = { .f = x };

#line 59
  return c.t;
}

#line 84
static inline /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__cc_t /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Control__getControl(void )
#line 84
{
  return /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__int2CC(* (volatile uint16_t * )356U);
}

#line 167
static inline void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Capture__default__captured(uint16_t n)
#line 167
{
}

# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
inline static void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Capture__captured(uint16_t time){
#line 92
  /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Capture__default__captured(time);
#line 92
}
#line 92
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline uint16_t /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Capture__getEvent(void )
#line 136
{
  return * (volatile uint16_t * )372U;
}

#line 169
static inline void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Compare__default__fired(void )
#line 169
{
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Compare__fired(void ){
#line 46
  /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Compare__default__fired();
#line 46
}
#line 46
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__cc_t /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__int2CC(uint16_t x)
#line 59
{
#line 59
  union /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2____nesc_unnamed4373 {
#line 59
    uint16_t f;
#line 59
    /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__cc_t t;
  } 
#line 59
  c = { .f = x };

#line 59
  return c.t;
}

#line 84
static inline /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__cc_t /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Control__getControl(void )
#line 84
{
  return /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__int2CC(* (volatile uint16_t * )358U);
}

#line 167
static inline void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Capture__default__captured(uint16_t n)
#line 167
{
}

# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
inline static void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Capture__captured(uint16_t time){
#line 92
  /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Capture__default__captured(time);
#line 92
}
#line 92
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline uint16_t /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Capture__getEvent(void )
#line 136
{
  return * (volatile uint16_t * )374U;
}

#line 169
static inline void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Compare__default__fired(void )
#line 169
{
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Compare__fired(void ){
#line 46
  /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Compare__default__fired();
#line 46
}
#line 46
# 157 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
static inline void /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__VectorTimerX1__fired(void )
#line 157
{
  uint8_t n = * (volatile uint16_t * )302U;

#line 159
  /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Event__fired(n >> 1);
}

# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
inline static void Msp430TimerCommonP__VectorTimerA1__fired(void ){
#line 39
  /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__VectorTimerX1__fired();
#line 39
}
#line 39
# 144 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
static inline void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__VectorTimerX0__fired(void )
#line 144
{
  /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Event__fired(0);
}

# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
inline static void Msp430TimerCommonP__VectorTimerB0__fired(void ){
#line 39
  /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__VectorTimerX0__fired();
#line 39
}
#line 39
# 171 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Timer__overflow(void )
#line 171
{
}

#line 171
static inline void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Timer__overflow(void )
#line 171
{
}

#line 171
static inline void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Timer__overflow(void )
#line 171
{
}

#line 171
static inline void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Timer__overflow(void )
#line 171
{
}

#line 171
static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Timer__overflow(void )
#line 171
{
}

#line 171
static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Timer__overflow(void )
#line 171
{
}

#line 171
static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Timer__overflow(void )
#line 171
{
}

# 114 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Msp430Timer__overflow(void )
{
}

#line 114
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Timer__overflow(void )
{
}

#line 114
static inline void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Timer__overflow(void )
{
}

# 58 "/home/wtiberti/WSN/tinyos/tos/lib/timer/CounterToLocalTimeC.nc"
static inline void /*HilTimerMilliC.CounterToLocalTimeC*/CounterToLocalTimeC__0__Counter__overflow(void )
{
}

# 177 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Counter__overflow(void )
{
}

# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static void /*CounterMilli32C.Transform*/TransformCounterC__0__Counter__overflow(void ){
#line 82
  /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Counter__overflow();
#line 82
  /*HilTimerMilliC.CounterToLocalTimeC*/CounterToLocalTimeC__0__Counter__overflow();
#line 82
}
#line 82
# 133 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
static inline void /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__overflow(void )
{
  /* atomic removed: atomic calls only */
  {
    /*CounterMilli32C.Transform*/TransformCounterC__0__m_upper++;
    if ((/*CounterMilli32C.Transform*/TransformCounterC__0__m_upper & /*CounterMilli32C.Transform*/TransformCounterC__0__OVERFLOW_MASK) == 0) {
      /*CounterMilli32C.Transform*/TransformCounterC__0__Counter__overflow();
      }
  }
}

# 177 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Counter__overflow(void )
{
}

# 58 "/home/wtiberti/WSN/tinyos/tos/lib/timer/CounterToLocalTimeC.nc"
static inline void /*CC2420PacketC.CounterToLocalTimeC*/CounterToLocalTimeC__1__Counter__overflow(void )
{
}

# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static void /*Counter32khz32C.Transform*/TransformCounterC__1__Counter__overflow(void ){
#line 82
  /*CC2420PacketC.CounterToLocalTimeC*/CounterToLocalTimeC__1__Counter__overflow();
#line 82
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Counter__overflow();
#line 82
}
#line 82
# 133 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
static inline void /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__overflow(void )
{
  /* atomic removed: atomic calls only */
  {
    /*Counter32khz32C.Transform*/TransformCounterC__1__m_upper++;
    if ((/*Counter32khz32C.Transform*/TransformCounterC__1__m_upper & /*Counter32khz32C.Transform*/TransformCounterC__1__OVERFLOW_MASK) == 0) {
      /*Counter32khz32C.Transform*/TransformCounterC__1__Counter__overflow();
      }
  }
}

# 58 "/home/wtiberti/WSN/tinyos/tos/lib/timer/CounterToLocalTimeC.nc"
static inline void /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__overflow(void )
{
}

# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static void /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__Counter__overflow(void ){
#line 82
  /*LocalTimeHybridMicroC.CounterToLocalTimeC*/CounterToLocalTimeC__2__Counter__overflow();
#line 82
}
#line 82
# 133 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
static inline void /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__overflow(void )
{
  /* atomic removed: atomic calls only */
  {
    /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__m_upper++;
    if ((/*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__m_upper & /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__OVERFLOW_MASK) == 0) {
      /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__Counter__overflow();
      }
  }
}

# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static void Msp430HybridAlarmCounterP__Counter2ghz__overflow(void ){
#line 82
  /*LocalTimeHybridMicroC.TransformCounterC*/TransformCounterC__2__CounterFrom__overflow();
#line 82
}
#line 82
# 124 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430HybridAlarmCounterP.nc"
static inline void Msp430HybridAlarmCounterP__Counter32khz__overflow(void )
#line 124
{
  Msp430HybridAlarmCounterP__Counter2ghz__overflow();
}

# 230 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__Counter__overflow(void )
#line 230
{
}

# 82 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Counter.nc"
inline static void /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__overflow(void ){
#line 82
  /*Msp430Uart1P.UartP*/Msp430UartP__0__Counter__overflow();
#line 82
  Msp430HybridAlarmCounterP__Counter32khz__overflow();
#line 82
  /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__overflow();
#line 82
  /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__overflow();
#line 82
}
#line 82
# 64 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430CounterC.nc"
static inline void /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Msp430Timer__overflow(void )
{
  /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Counter__overflow();
}

# 48 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
inline static void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__overflow(void ){
#line 48
  /*Msp430Counter32khzC.Counter*/Msp430CounterC__0__Msp430Timer__overflow();
#line 48
  /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Timer__overflow();
#line 48
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Timer__overflow();
#line 48
  /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Msp430Timer__overflow();
#line 48
  /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Timer__overflow();
#line 48
  /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Timer__overflow();
#line 48
  /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Timer__overflow();
#line 48
  /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Timer__overflow();
#line 48
  /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Timer__overflow();
#line 48
  /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Timer__overflow();
#line 48
  /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Timer__overflow();
#line 48
}
#line 48
# 162 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
static inline void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Overflow__fired(void )
{
  /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__overflow();
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
inline static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__fired(void ){
#line 78
  /*HilTimerMilliC.AlarmToTimerC*/AlarmToTimerC__0__Alarm__fired();
#line 78
}
#line 78
# 162 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__fired(void )
{
  /* atomic removed: atomic calls only */
  {
    if (/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_dt == 0) 
      {
        /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__fired();
      }
    else 
      {
        /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__set_alarm();
      }
  }
}

# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__fired(void ){
#line 78
  /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__fired();
#line 78
}
#line 78
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Compare__fired(void )
{
  /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430TimerControl__disableEvents();
  /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Alarm__fired();
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Compare__fired(void ){
#line 46
  /*HilTimerMilliC.AlarmMilli32C.AlarmFrom.Msp430Alarm*/Msp430AlarmC__0__Msp430Compare__fired();
#line 46
}
#line 46
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline uint16_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Capture__getEvent(void )
#line 136
{
  return * (volatile uint16_t * )402U;
}

#line 167
static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Capture__default__captured(uint16_t n)
#line 167
{
}

# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
inline static void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Capture__captured(uint16_t time){
#line 92
  /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Capture__default__captured(time);
#line 92
}
#line 92
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__cc_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__int2CC(uint16_t x)
#line 59
{
#line 59
  union /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3____nesc_unnamed4374 {
#line 59
    uint16_t f;
#line 59
    /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__cc_t t;
  } 
#line 59
  c = { .f = x };

#line 59
  return c.t;
}

#line 84
static inline /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__cc_t /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__getControl(void )
#line 84
{
  return /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__int2CC(* (volatile uint16_t * )386U);
}

#line 160
static inline void /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Event__fired(void )
#line 160
{
  if (/*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Control__getControl().cap) {
    /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Capture__captured(/*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Capture__getEvent());
    }
  else {
#line 164
    /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Compare__fired();
    }
}


static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Compare__default__fired(void )
#line 169
{
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Compare__fired(void ){
#line 46
  /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Compare__default__fired();
#line 46
}
#line 46
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline uint16_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Capture__getEvent(void )
#line 136
{
  return * (volatile uint16_t * )404U;
}

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
# 98 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline uint8_t /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__getRaw(void )
#line 98
{
#line 98
  return * (volatile uint8_t * )28U & (0x01 << 1);
}

#line 99
static inline bool /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__get(void )
#line 99
{
#line 99
  return /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__getRaw() != 0;
}

# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static bool /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__HplGeneralIO__get(void ){
#line 74
  unsigned char __nesc_result;
#line 74

#line 74
  __nesc_result = /*HplMsp430GeneralIOC.P41*/HplMsp430GeneralIOP__25__IO__get();
#line 74

#line 74
  return __nesc_result;
#line 74
}
#line 74
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline bool /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__GeneralIO__get(void )
#line 51
{
#line 51
  return /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__HplGeneralIO__get();
}

# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static bool CC2420TransmitP__SFD__get(void ){
#line 43
  unsigned char __nesc_result;
#line 43

#line 43
  __nesc_result = /*HplCC2420PinsC.SFDM*/Msp430GpioC__8__GeneralIO__get();
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
# 78 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/GpioCaptureC.nc"
static inline error_t /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__captureFallingEdge(void )
#line 78
{
  return /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__enableCapture(MSP430TIMER_CM_FALLING);
}

# 54 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
inline static error_t CC2420TransmitP__CaptureSFD__captureFallingEdge(void ){
#line 54
  enum __nesc_unnamed4242 __nesc_result;
#line 54

#line 54
  __nesc_result = /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__captureFallingEdge();
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
  __nesc_result = /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__getNow();
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

  /* atomic removed: atomic calls only */
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

                  return;
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
}

# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioCapture.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__captured(uint16_t time){
#line 61
  CC2420TransmitP__CaptureSFD__captured(time);
#line 61
}
#line 61
# 156 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Capture__clearOverflow(void )
#line 156
{
  * (volatile uint16_t * )388U &= ~0x0002;
}

# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430Capture__clearOverflow(void ){
#line 74
  /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Capture__clearOverflow();
#line 74
}
#line 74
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__clearPendingInterrupt(void )
#line 92
{
  * (volatile uint16_t * )388U &= ~0x0001;
}

# 43 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__clearPendingInterrupt(void ){
#line 43
  /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__clearPendingInterrupt();
#line 43
}
#line 43
# 89 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/GpioCaptureC.nc"
static inline void /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430Capture__captured(uint16_t time)
#line 89
{
  /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__clearPendingInterrupt();
  /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430Capture__clearOverflow();
  /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Capture__captured(time);
}

# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
inline static void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Capture__captured(uint16_t time){
#line 92
  /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430Capture__captured(time);
#line 92
}
#line 92
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__cc_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__int2CC(uint16_t x)
#line 59
{
#line 59
  union /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4____nesc_unnamed4375 {
#line 59
    uint16_t f;
#line 59
    /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__cc_t t;
  } 
#line 59
  c = { .f = x };

#line 59
  return c.t;
}

#line 84
static inline /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__cc_t /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__getControl(void )
#line 84
{
  return /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__int2CC(* (volatile uint16_t * )388U);
}

#line 160
static inline void /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Event__fired(void )
#line 160
{
  if (/*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Control__getControl().cap) {
    /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Capture__captured(/*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Capture__getEvent());
    }
  else {
#line 164
    /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Compare__fired();
    }
}

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

# 98 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static inline uint8_t /*HplMsp430GeneralIOC.P14*/HplMsp430GeneralIOP__4__IO__getRaw(void )
#line 98
{
#line 98
  return * (volatile uint8_t * )32U & (0x01 << 4);
}

#line 99
static inline bool /*HplMsp430GeneralIOC.P14*/HplMsp430GeneralIOP__4__IO__get(void )
#line 99
{
#line 99
  return /*HplMsp430GeneralIOC.P14*/HplMsp430GeneralIOP__4__IO__getRaw() != 0;
}

# 74 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIO.nc"
inline static bool /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__HplGeneralIO__get(void ){
#line 74
  unsigned char __nesc_result;
#line 74

#line 74
  __nesc_result = /*HplMsp430GeneralIOC.P14*/HplMsp430GeneralIOP__4__IO__get();
#line 74

#line 74
  return __nesc_result;
#line 74
}
#line 74
# 51 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/Msp430GpioC.nc"
static inline bool /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__GeneralIO__get(void )
#line 51
{
#line 51
  return /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__HplGeneralIO__get();
}

# 43 "/home/wtiberti/WSN/tinyos/tos/interfaces/GeneralIO.nc"
inline static bool CC2420TransmitP__CCA__get(void ){
#line 43
  unsigned char __nesc_result;
#line 43

#line 43
  __nesc_result = /*HplCC2420PinsC.CCAM*/Msp430GpioC__3__GeneralIO__get();
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
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__fired(void ){
#line 78
  CC2420TransmitP__BackoffTimer__fired();
#line 78
  CC2420ControlP__StartupTimer__fired();
#line 78
}
#line 78
# 162 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__fired(void )
{
  /* atomic removed: atomic calls only */
  {
    if (/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_dt == 0) 
      {
        /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__fired();
      }
    else 
      {
        /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__set_alarm();
      }
  }
}

# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__fired(void ){
#line 78
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__fired();
#line 78
}
#line 78
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Compare__fired(void )
{
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430TimerControl__disableEvents();
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Alarm__fired();
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Compare__fired(void ){
#line 46
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.AlarmC.Msp430Alarm*/Msp430AlarmC__1__Msp430Compare__fired();
#line 46
}
#line 46
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline uint16_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Capture__getEvent(void )
#line 136
{
  return * (volatile uint16_t * )406U;
}

#line 167
static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Capture__default__captured(uint16_t n)
#line 167
{
}

# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
inline static void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Capture__captured(uint16_t time){
#line 92
  /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Capture__default__captured(time);
#line 92
}
#line 92
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__cc_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__int2CC(uint16_t x)
#line 59
{
#line 59
  union /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5____nesc_unnamed4376 {
#line 59
    uint16_t f;
#line 59
    /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__cc_t t;
  } 
#line 59
  c = { .f = x };

#line 59
  return c.t;
}

#line 84
static inline /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__cc_t /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__getControl(void )
#line 84
{
  return /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__int2CC(* (volatile uint16_t * )390U);
}

#line 160
static inline void /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Event__fired(void )
#line 160
{
  if (/*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Control__getControl().cap) {
    /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Capture__captured(/*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Capture__getEvent());
    }
  else {
#line 164
    /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Compare__fired();
    }
}

#line 109
static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__enableEvents(void )
#line 109
{
  * (volatile uint16_t * )354U |= 0x0010;
}

# 76 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430TimerControl__enableEvents(void ){
#line 76
  /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__enableEvents();
#line 76
}
#line 76
# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__clearPendingInterrupt(void )
#line 92
{
  * (volatile uint16_t * )354U &= ~0x0001;
}

# 43 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430TimerControl__clearPendingInterrupt(void ){
#line 43
  /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__clearPendingInterrupt();
#line 43
}
#line 43
# 140 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Compare__setEvent(uint16_t x)
#line 140
{
  * (volatile uint16_t * )370U = x;
}

# 42 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Compare__setEvent(uint16_t time){
#line 42
  /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Compare__setEvent(time);
#line 42
}
#line 42
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
inline static uint16_t /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Timer__get(void ){
#line 45
  unsigned short __nesc_result;
#line 45

#line 45
  __nesc_result = /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Timer__get();
#line 45

#line 45
  return __nesc_result;
#line 45
}
#line 45
# 148 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Compare__setEventFromNow(uint16_t delta)
#line 148
{
  * (volatile uint16_t * )370U = /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Timer__get() + delta;
}

# 44 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Compare__setEventFromNow(uint16_t delta){
#line 44
  /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Compare__setEventFromNow(delta);
#line 44
}
#line 44
# 45 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Timer.nc"
inline static uint16_t /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Timer__get(void ){
#line 45
  unsigned short __nesc_result;
#line 45

#line 45
  __nesc_result = /*Msp430TimerC.Msp430TimerA*/Msp430TimerP__0__Timer__get();
#line 45

#line 45
  return __nesc_result;
#line 45
}
#line 45
# 81 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__startAt(uint16_t t0, uint16_t dt)
{
  /* atomic removed: atomic calls only */
  {
    uint16_t now = /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Timer__get();
    uint16_t elapsed = now - t0;

#line 87
    if (elapsed >= dt) 
      {
        /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Compare__setEventFromNow(2);
      }
    else 
      {
        uint16_t remaining = dt - elapsed;

#line 94
        if (remaining <= 2) {
          /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Compare__setEventFromNow(2);
          }
        else {
#line 97
          /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430Compare__setEvent(now + remaining);
          }
      }
#line 99
    /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430TimerControl__clearPendingInterrupt();
    /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Msp430TimerControl__enableEvents();
  }
}

# 103 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void Msp430HybridAlarmCounterP__AlarmMicro__startAt(Msp430HybridAlarmCounterP__AlarmMicro__size_type t0, Msp430HybridAlarmCounterP__AlarmMicro__size_type dt){
#line 103
  /*Msp430HybridAlarmCounterC.AlarmMicro16C.Msp430Alarm*/Msp430AlarmC__3__Alarm__startAt(t0, dt);
#line 103
}
#line 103
# 163 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430HybridAlarmCounterP.nc"
static inline void Msp430HybridAlarmCounterP__Alarm32khz__fired(void )
#line 163
{
  uint16_t tMicro;
#line 164
  uint16_t t32khz;
  uint32_t t2ghz;
#line 165
  uint32_t dt;


  Msp430HybridAlarmCounterP__now(&t32khz, &tMicro, &t2ghz);


  dt = Msp430HybridAlarmCounterP__fireTime - t2ghz;

  Msp430HybridAlarmCounterP__AlarmMicro__startAt(tMicro, dt >> 11);
}

# 78 "/home/wtiberti/WSN/tinyos/tos/lib/timer/Alarm.nc"
inline static void /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Alarm__fired(void ){
#line 78
  Msp430HybridAlarmCounterP__Alarm32khz__fired();
#line 78
}
#line 78
# 113 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Control__disableEvents(void )
#line 113
{
  * (volatile uint16_t * )392U &= ~0x0010;
}

# 77 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerControl.nc"
inline static void /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Msp430TimerControl__disableEvents(void ){
#line 77
  /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Control__disableEvents();
#line 77
}
#line 77
# 70 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430AlarmC.nc"
static inline void /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Msp430Compare__fired(void )
{
  /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Msp430TimerControl__disableEvents();
  /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Alarm__fired();
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Compare__fired(void ){
#line 46
  /*Msp430HybridAlarmCounterC.Alarm32khz16C.Msp430Alarm*/Msp430AlarmC__2__Msp430Compare__fired();
#line 46
}
#line 46
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline uint16_t /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Capture__getEvent(void )
#line 136
{
  return * (volatile uint16_t * )408U;
}

#line 167
static inline void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Capture__default__captured(uint16_t n)
#line 167
{
}

# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
inline static void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Capture__captured(uint16_t time){
#line 92
  /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Capture__default__captured(time);
#line 92
}
#line 92
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__cc_t /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__int2CC(uint16_t x)
#line 59
{
#line 59
  union /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6____nesc_unnamed4377 {
#line 59
    uint16_t f;
#line 59
    /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__cc_t t;
  } 
#line 59
  c = { .f = x };

#line 59
  return c.t;
}

#line 84
static inline /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__cc_t /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Control__getControl(void )
#line 84
{
  return /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__int2CC(* (volatile uint16_t * )392U);
}

#line 160
static inline void /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Event__fired(void )
#line 160
{
  if (/*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Control__getControl().cap) {
    /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Capture__captured(/*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Capture__getEvent());
    }
  else {
#line 164
    /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Compare__fired();
    }
}


static inline void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Compare__default__fired(void )
#line 169
{
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Compare__fired(void ){
#line 46
  /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Compare__default__fired();
#line 46
}
#line 46
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline uint16_t /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Capture__getEvent(void )
#line 136
{
  return * (volatile uint16_t * )410U;
}

#line 167
static inline void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Capture__default__captured(uint16_t n)
#line 167
{
}

# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
inline static void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Capture__captured(uint16_t time){
#line 92
  /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Capture__default__captured(time);
#line 92
}
#line 92
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__cc_t /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__int2CC(uint16_t x)
#line 59
{
#line 59
  union /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7____nesc_unnamed4378 {
#line 59
    uint16_t f;
#line 59
    /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__cc_t t;
  } 
#line 59
  c = { .f = x };

#line 59
  return c.t;
}

#line 84
static inline /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__cc_t /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Control__getControl(void )
#line 84
{
  return /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__int2CC(* (volatile uint16_t * )394U);
}

#line 160
static inline void /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Event__fired(void )
#line 160
{
  if (/*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Control__getControl().cap) {
    /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Capture__captured(/*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Capture__getEvent());
    }
  else {
#line 164
    /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Compare__fired();
    }
}


static inline void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Compare__default__fired(void )
#line 169
{
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Compare__fired(void ){
#line 46
  /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Compare__default__fired();
#line 46
}
#line 46
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline uint16_t /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Capture__getEvent(void )
#line 136
{
  return * (volatile uint16_t * )412U;
}

#line 167
static inline void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Capture__default__captured(uint16_t n)
#line 167
{
}

# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
inline static void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Capture__captured(uint16_t time){
#line 92
  /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Capture__default__captured(time);
#line 92
}
#line 92
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__cc_t /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__int2CC(uint16_t x)
#line 59
{
#line 59
  union /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8____nesc_unnamed4379 {
#line 59
    uint16_t f;
#line 59
    /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__cc_t t;
  } 
#line 59
  c = { .f = x };

#line 59
  return c.t;
}

#line 84
static inline /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__cc_t /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Control__getControl(void )
#line 84
{
  return /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__int2CC(* (volatile uint16_t * )396U);
}

#line 160
static inline void /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Event__fired(void )
#line 160
{
  if (/*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Control__getControl().cap) {
    /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Capture__captured(/*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Capture__getEvent());
    }
  else {
#line 164
    /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Compare__fired();
    }
}


static inline void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Compare__default__fired(void )
#line 169
{
}

# 46 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Compare.nc"
inline static void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Compare__fired(void ){
#line 46
  /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Compare__default__fired();
#line 46
}
#line 46
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline uint16_t /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Capture__getEvent(void )
#line 136
{
  return * (volatile uint16_t * )414U;
}

#line 167
static inline void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Capture__default__captured(uint16_t n)
#line 167
{
}

# 92 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430Capture.nc"
inline static void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Capture__captured(uint16_t time){
#line 92
  /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Capture__default__captured(time);
#line 92
}
#line 92
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static inline  /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__cc_t /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__int2CC(uint16_t x)
#line 59
{
#line 59
  union /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9____nesc_unnamed4380 {
#line 59
    uint16_t f;
#line 59
    /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__cc_t t;
  } 
#line 59
  c = { .f = x };

#line 59
  return c.t;
}

#line 84
static inline /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__cc_t /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Control__getControl(void )
#line 84
{
  return /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__int2CC(* (volatile uint16_t * )398U);
}

#line 160
static inline void /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Event__fired(void )
#line 160
{
  if (/*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Control__getControl().cap) {
    /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Capture__captured(/*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Capture__getEvent());
    }
  else {
#line 164
    /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Compare__fired();
    }
}

# 157 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
static inline void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__VectorTimerX1__fired(void )
#line 157
{
  uint8_t n = * (volatile uint16_t * )286U;

#line 159
  /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Event__fired(n >> 1);
}

# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
inline static void Msp430TimerCommonP__VectorTimerB1__fired(void ){
#line 39
  /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__VectorTimerX1__fired();
#line 39
}
#line 39
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
inline static void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__Interrupt__fired(void ){
#line 68
  CC2420ReceiveP__InterruptFIFOP__fired();
#line 68
}
#line 68
# 93 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/Msp430InterruptC.nc"
static inline void /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__fired(void )
#line 93
{





  /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__Interrupt__fired();
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port10__fired(void ){
#line 85
  /*HplCC2420InterruptsC.InterruptFIFOPC*/Msp430InterruptC__1__HplInterrupt__fired();
#line 85
}
#line 85
# 134 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port11__clear(void )
#line 134
{
#line 134
  P1IFG &= ~(1 << 1);
}

#line 107
static inline void HplMsp430InterruptP__Port11__default__fired(void )
#line 107
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port11__fired(void ){
#line 85
  HplMsp430InterruptP__Port11__default__fired();
#line 85
}
#line 85
# 135 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port12__clear(void )
#line 135
{
#line 135
  P1IFG &= ~(1 << 2);
}

#line 108
static inline void HplMsp430InterruptP__Port12__default__fired(void )
#line 108
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port12__fired(void ){
#line 85
  HplMsp430InterruptP__Port12__default__fired();
#line 85
}
#line 85
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port13__clear(void )
#line 136
{
#line 136
  P1IFG &= ~(1 << 3);
}

#line 109
static inline void HplMsp430InterruptP__Port13__default__fired(void )
#line 109
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port13__fired(void ){
#line 85
  HplMsp430InterruptP__Port13__default__fired();
#line 85
}
#line 85
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
# 61 "/home/wtiberti/WSN/tinyos/tos/interfaces/GpioInterrupt.nc"
inline static error_t CC2420ControlP__InterruptCCA__disable(void ){
#line 61
  enum __nesc_unnamed4242 __nesc_result;
#line 61

#line 61
  __nesc_result = /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__Interrupt__disable();
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
inline static void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__Interrupt__fired(void ){
#line 68
  CC2420ControlP__InterruptCCA__fired();
#line 68
}
#line 68
# 93 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/Msp430InterruptC.nc"
static inline void /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__fired(void )
#line 93
{





  /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__Interrupt__fired();
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port14__fired(void ){
#line 85
  /*HplCC2420InterruptsC.InterruptCCAC*/Msp430InterruptC__0__HplInterrupt__fired();
#line 85
}
#line 85
# 138 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port15__clear(void )
#line 138
{
#line 138
  P1IFG &= ~(1 << 5);
}

#line 111
static inline void HplMsp430InterruptP__Port15__default__fired(void )
#line 111
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port15__fired(void ){
#line 85
  HplMsp430InterruptP__Port15__default__fired();
#line 85
}
#line 85
# 139 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port16__clear(void )
#line 139
{
#line 139
  P1IFG &= ~(1 << 6);
}

#line 112
static inline void HplMsp430InterruptP__Port16__default__fired(void )
#line 112
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port16__fired(void ){
#line 85
  HplMsp430InterruptP__Port16__default__fired();
#line 85
}
#line 85
# 140 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port17__clear(void )
#line 140
{
#line 140
  P1IFG &= ~(1 << 7);
}

#line 113
static inline void HplMsp430InterruptP__Port17__default__fired(void )
#line 113
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port17__fired(void ){
#line 85
  HplMsp430InterruptP__Port17__default__fired();
#line 85
}
#line 85
# 267 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port20__clear(void )
#line 267
{
#line 267
  P2IFG &= ~(1 << 0);
}

#line 240
static inline void HplMsp430InterruptP__Port20__default__fired(void )
#line 240
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port20__fired(void ){
#line 85
  HplMsp430InterruptP__Port20__default__fired();
#line 85
}
#line 85
# 268 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port21__clear(void )
#line 268
{
#line 268
  P2IFG &= ~(1 << 1);
}

#line 241
static inline void HplMsp430InterruptP__Port21__default__fired(void )
#line 241
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port21__fired(void ){
#line 85
  HplMsp430InterruptP__Port21__default__fired();
#line 85
}
#line 85
# 269 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port22__clear(void )
#line 269
{
#line 269
  P2IFG &= ~(1 << 2);
}

#line 242
static inline void HplMsp430InterruptP__Port22__default__fired(void )
#line 242
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port22__fired(void ){
#line 85
  HplMsp430InterruptP__Port22__default__fired();
#line 85
}
#line 85
# 270 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port23__clear(void )
#line 270
{
#line 270
  P2IFG &= ~(1 << 3);
}

#line 243
static inline void HplMsp430InterruptP__Port23__default__fired(void )
#line 243
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port23__fired(void ){
#line 85
  HplMsp430InterruptP__Port23__default__fired();
#line 85
}
#line 85
# 271 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port24__clear(void )
#line 271
{
#line 271
  P2IFG &= ~(1 << 4);
}

#line 244
static inline void HplMsp430InterruptP__Port24__default__fired(void )
#line 244
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port24__fired(void ){
#line 85
  HplMsp430InterruptP__Port24__default__fired();
#line 85
}
#line 85
# 272 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port25__clear(void )
#line 272
{
#line 272
  P2IFG &= ~(1 << 5);
}

#line 245
static inline void HplMsp430InterruptP__Port25__default__fired(void )
#line 245
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port25__fired(void ){
#line 85
  HplMsp430InterruptP__Port25__default__fired();
#line 85
}
#line 85
# 273 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port26__clear(void )
#line 273
{
#line 273
  P2IFG &= ~(1 << 6);
}

#line 246
static inline void HplMsp430InterruptP__Port26__default__fired(void )
#line 246
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port26__fired(void ){
#line 85
  HplMsp430InterruptP__Port26__default__fired();
#line 85
}
#line 85
# 274 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
static inline void HplMsp430InterruptP__Port27__clear(void )
#line 274
{
#line 274
  P2IFG &= ~(1 << 7);
}

#line 247
static inline void HplMsp430InterruptP__Port27__default__fired(void )
#line 247
{
}

# 85 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430Interrupt.nc"
inline static void HplMsp430InterruptP__Port27__fired(void ){
#line 85
  HplMsp430InterruptP__Port27__default__fired();
#line 85
}
#line 85
# 331 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline uint8_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ArbiterInfo__userId(void )
#line 331
{
  return /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId;
}

# 98 "/home/wtiberti/WSN/tinyos/tos/interfaces/ArbiterInfo.nc"
inline static uint8_t /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__ArbiterInfo__userId(void ){
#line 98
  unsigned char __nesc_result;
#line 98

#line 98
  __nesc_result = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ArbiterInfo__userId();
#line 98

#line 98
  return __nesc_result;
#line 98
}
#line 98
# 332 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
static inline void HplMsp430Usart0P__Usart__disableRxIntr(void )
#line 332
{
  HplMsp430Usart0P__IE1 &= ~0x40;
}

# 177 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__disableRxIntr(void ){
#line 177
  HplMsp430Usart0P__Usart__disableRxIntr();
#line 177
}
#line 177
# 231 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartInterrupts__rxDone(uint8_t data)
#line 231
{

  if (/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_rx_buf) {
    /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_rx_buf[/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_pos - 1] = data;
    }
  if (/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_pos < /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_len) {
    /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__continueOp();
    }
  else 
#line 238
    {
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__disableRxIntr();
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone();
    }
}

# 65 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
static inline void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__default__rxDone(uint8_t id, uint8_t data)
#line 65
{
}

# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
inline static void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__rxDone(uint8_t arg_0x7f2557b16cd0, uint8_t data){
#line 54
  switch (arg_0x7f2557b16cd0) {
#line 54
    case /*CC2420SpiWireC.HplCC2420SpiC.SpiC.UsartC*/Msp430Usart0C__0__CLIENT_ID:
#line 54
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartInterrupts__rxDone(data);
#line 54
      break;
#line 54
    default:
#line 54
      /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__default__rxDone(arg_0x7f2557b16cd0, data);
#line 54
      break;
#line 54
    }
#line 54
}
#line 54
# 90 "/home/wtiberti/WSN/tinyos/tos/interfaces/ArbiterInfo.nc"
inline static bool /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__ArbiterInfo__inUse(void ){
#line 90
  unsigned char __nesc_result;
#line 90

#line 90
  __nesc_result = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ArbiterInfo__inUse();
#line 90

#line 90
  return __nesc_result;
#line 90
}
#line 90
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
static inline void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__RawInterrupts__rxDone(uint8_t data)
#line 54
{
  if (/*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__ArbiterInfo__inUse()) {
    /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__rxDone(/*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__ArbiterInfo__userId(), data);
    }
}

# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
inline static void HplMsp430Usart0P__Interrupts__rxDone(uint8_t data){
#line 54
  /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__RawInterrupts__rxDone(data);
#line 54
}
#line 54
# 378 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwnerInfo__default__inUse(void )
#line 378
{
  return FALSE;
}

# 9 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwnerInfo.nc"
inline static bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwnerInfo__inUse(void ){
#line 9
  unsigned char __nesc_result;
#line 9

#line 9
  __nesc_result = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwnerInfo__default__inUse();
#line 9

#line 9
  return __nesc_result;
#line 9
}
#line 9
# 64 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430I2C0P.nc"
static inline bool HplMsp430I2C0P__HplI2C__isI2C(void )
#line 64
{
  /* atomic removed: atomic calls only */
#line 65
  {
    unsigned char __nesc_temp = 
#line 65
    HplMsp430I2C0P__U0CTL & 0x20 && HplMsp430I2C0P__U0CTL & 0x04 && HplMsp430I2C0P__U0CTL & 0x01;

#line 65
    return __nesc_temp;
  }
}

# 6 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430I2C.nc"
inline static bool HplMsp430Usart0P__HplI2C__isI2C(void ){
#line 6
  unsigned char __nesc_result;
#line 6

#line 6
  __nesc_result = HplMsp430I2C0P__HplI2C__isI2C();
#line 6

#line 6
  return __nesc_result;
#line 6
}
#line 6
# 66 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
static inline void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__I2CInterrupts__default__fired(uint8_t id)
#line 66
{
}

# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430I2CInterrupts.nc"
inline static void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__I2CInterrupts__fired(uint8_t arg_0x7f2557b15b80){
#line 39
    /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__I2CInterrupts__default__fired(arg_0x7f2557b15b80);
#line 39
}
#line 39
# 59 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
static inline void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__RawI2CInterrupts__fired(void )
#line 59
{
  if (/*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__ArbiterInfo__inUse()) {
    /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__I2CInterrupts__fired(/*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__ArbiterInfo__userId());
    }
}

# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430I2CInterrupts.nc"
inline static void HplMsp430Usart0P__I2CInterrupts__fired(void ){
#line 39
  /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__RawI2CInterrupts__fired();
#line 39
}
#line 39
# 249 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static inline void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartInterrupts__txDone(void )
#line 249
{
}

# 64 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
static inline void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__default__txDone(uint8_t id)
#line 64
{
}

# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
inline static void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__txDone(uint8_t arg_0x7f2557b16cd0){
#line 49
  switch (arg_0x7f2557b16cd0) {
#line 49
    case /*CC2420SpiWireC.HplCC2420SpiC.SpiC.UsartC*/Msp430Usart0C__0__CLIENT_ID:
#line 49
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__UsartInterrupts__txDone();
#line 49
      break;
#line 49
    default:
#line 49
      /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__default__txDone(arg_0x7f2557b16cd0);
#line 49
      break;
#line 49
    }
#line 49
}
#line 49
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
static inline void /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__RawInterrupts__txDone(void )
#line 49
{
  if (/*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__ArbiterInfo__inUse()) {
    /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__Interrupts__txDone(/*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__ArbiterInfo__userId());
    }
}

# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
inline static void HplMsp430Usart0P__Interrupts__txDone(void ){
#line 49
  /*Msp430UsartShare0P.UsartShareP*/Msp430UsartShareP__0__RawInterrupts__txDone();
#line 49
}
#line 49
# 331 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline uint8_t /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ArbiterInfo__userId(void )
#line 331
{
  return /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__resId;
}

# 98 "/home/wtiberti/WSN/tinyos/tos/interfaces/ArbiterInfo.nc"
inline static uint8_t /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__ArbiterInfo__userId(void ){
#line 98
  unsigned char __nesc_result;
#line 98

#line 98
  __nesc_result = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ArbiterInfo__userId();
#line 98

#line 98
  return __nesc_result;
#line 98
}
#line 98
# 243 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__default__receivedByte(uint8_t id, uint8_t byte)
#line 243
{
}

# 79 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
inline static void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__receivedByte(uint8_t arg_0x7f25572674c0, uint8_t byte){
#line 79
    /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__default__receivedByte(arg_0x7f25572674c0, byte);
#line 79
}
#line 79
# 244 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__default__receiveDone(uint8_t id, uint8_t *buf, uint16_t len, error_t error)
#line 244
{
}

# 99 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
inline static void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__receiveDone(uint8_t arg_0x7f25572674c0, uint8_t * buf, uint16_t len, error_t error){
#line 99
    /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__default__receiveDone(arg_0x7f25572674c0, buf, len, error);
#line 99
}
#line 99
# 136 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartInterrupts__rxDone(uint8_t id, uint8_t data)
#line 136
{
  if (/*Msp430Uart1P.UartP*/Msp430UartP__0__m_rx_buf) {
      /*Msp430Uart1P.UartP*/Msp430UartP__0__m_rx_buf[/*Msp430Uart1P.UartP*/Msp430UartP__0__m_rx_pos++] = data;
      if (/*Msp430Uart1P.UartP*/Msp430UartP__0__m_rx_pos >= /*Msp430Uart1P.UartP*/Msp430UartP__0__m_rx_len) {
          uint8_t *buf = /*Msp430Uart1P.UartP*/Msp430UartP__0__m_rx_buf;

#line 141
          /*Msp430Uart1P.UartP*/Msp430UartP__0__m_rx_buf = (void *)0;
          /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__receiveDone(id, buf, /*Msp430Uart1P.UartP*/Msp430UartP__0__m_rx_len, SUCCESS);
        }
    }
  else 
#line 144
    {
      /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__receivedByte(id, data);
    }
}

# 65 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
static inline void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__default__rxDone(uint8_t id, uint8_t data)
#line 65
{
}

# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
inline static void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__rxDone(uint8_t arg_0x7f2557b16cd0, uint8_t data){
#line 54
  switch (arg_0x7f2557b16cd0) {
#line 54
    case /*PlatformSerialC.UartC.UsartC*/Msp430Usart1C__0__CLIENT_ID:
#line 54
      /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartInterrupts__rxDone(/*PlatformSerialC.UartC*/Msp430Uart1C__0__CLIENT_ID, data);
#line 54
      break;
#line 54
    default:
#line 54
      /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__default__rxDone(arg_0x7f2557b16cd0, data);
#line 54
      break;
#line 54
    }
#line 54
}
#line 54
# 90 "/home/wtiberti/WSN/tinyos/tos/interfaces/ArbiterInfo.nc"
inline static bool /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__ArbiterInfo__inUse(void ){
#line 90
  unsigned char __nesc_result;
#line 90

#line 90
  __nesc_result = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ArbiterInfo__inUse();
#line 90

#line 90
  return __nesc_result;
#line 90
}
#line 90
# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
static inline void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__RawInterrupts__rxDone(uint8_t data)
#line 54
{
  if (/*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__ArbiterInfo__inUse()) {
    /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__rxDone(/*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__ArbiterInfo__userId(), data);
    }
}

# 54 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
inline static void HplMsp430Usart1P__Interrupts__rxDone(uint8_t data){
#line 54
  /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__RawInterrupts__rxDone(data);
#line 54
}
#line 54
# 378 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline bool /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwnerInfo__default__inUse(void )
#line 378
{
  return FALSE;
}

# 9 "/home/wtiberti/WSN/tinyos/tos/interfaces/ResourceDefaultOwnerInfo.nc"
inline static bool /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwnerInfo__inUse(void ){
#line 9
  unsigned char __nesc_result;
#line 9

#line 9
  __nesc_result = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwnerInfo__default__inUse();
#line 9

#line 9
  return __nesc_result;
#line 9
}
#line 9
# 242 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__default__sendDone(uint8_t id, uint8_t *buf, uint16_t len, error_t error)
#line 242
{
}

# 57 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartStream.nc"
inline static void /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__sendDone(uint8_t arg_0x7f25572674c0, uint8_t * buf, uint16_t len, error_t error){
#line 57
    /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__default__sendDone(arg_0x7f25572674c0, buf, len, error);
#line 57
}
#line 57
# 368 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
static inline void HplMsp430Usart1P__Usart__tx(uint8_t data)
#line 368
{
  HplMsp430Usart1P__U1TXBUF = data;
}

# 220 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__tx(uint8_t data){
#line 220
  HplMsp430Usart1P__Usart__tx(data);
#line 220
}
#line 220
# 164 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline void /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartInterrupts__txDone(uint8_t id)
#line 164
{
  if (/*Msp430Uart1P.UartP*/Msp430UartP__0__current_owner != id) {
      uint8_t *buf = /*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_buf;

#line 167
      /*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_buf = (void *)0;
      /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__sendDone(id, buf, /*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_len, FAIL);
    }
  else {
#line 170
    if (/*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_pos < /*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_len) {
        /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__tx(/*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_buf[/*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_pos++]);
      }
    else {
        uint8_t *buf = /*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_buf;

#line 175
        /*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_buf = (void *)0;
        /*Msp430Uart1P.UartP*/Msp430UartP__0__UartStream__sendDone(id, buf, /*Msp430Uart1P.UartP*/Msp430UartP__0__m_tx_len, SUCCESS);
      }
    }
}

# 64 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
static inline void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__default__txDone(uint8_t id)
#line 64
{
}

# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
inline static void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__txDone(uint8_t arg_0x7f2557b16cd0){
#line 49
  switch (arg_0x7f2557b16cd0) {
#line 49
    case /*PlatformSerialC.UartC.UsartC*/Msp430Usart1C__0__CLIENT_ID:
#line 49
      /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartInterrupts__txDone(/*PlatformSerialC.UartC*/Msp430Uart1C__0__CLIENT_ID);
#line 49
      break;
#line 49
    default:
#line 49
      /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__default__txDone(arg_0x7f2557b16cd0);
#line 49
      break;
#line 49
    }
#line 49
}
#line 49
# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UsartShareP.nc"
static inline void /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__RawInterrupts__txDone(void )
#line 49
{
  if (/*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__ArbiterInfo__inUse()) {
    /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__Interrupts__txDone(/*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__ArbiterInfo__userId());
    }
}

# 49 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430UsartInterrupts.nc"
inline static void HplMsp430Usart1P__Interrupts__txDone(void ){
#line 49
  /*Msp430UsartShare1P.UsartShareP*/Msp430UsartShareP__1__RawInterrupts__txDone();
#line 49
}
#line 49
# 354 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
static inline void HplMsp430Usart1P__Usart__enableTxIntr(void )
#line 354
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 355
    {
      HplMsp430Usart1P__IFG2 &= ~0x20;
      HplMsp430Usart1P__IE2 |= 0x20;
    }
#line 358
    __nesc_atomic_end(__nesc_atomic); }
}

# 181 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__enableTxIntr(void ){
#line 181
  HplMsp430Usart1P__Usart__enableTxIntr();
#line 181
}
#line 181
# 323 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
static inline void HplMsp430Usart1P__Usart__clrTxIntr(void )
#line 323
{
  HplMsp430Usart1P__IFG2 &= ~0x20;
}

# 202 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__clrTxIntr(void ){
#line 202
  HplMsp430Usart1P__Usart__clrTxIntr();
#line 202
}
#line 202
# 302 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
static inline bool HplMsp430Usart1P__Usart__isTxIntrPending(void )
#line 302
{
  if (HplMsp430Usart1P__IFG2 & 0x20) {
      return TRUE;
    }
  return FALSE;
}

# 187 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static bool /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__isTxIntrPending(void ){
#line 187
  unsigned char __nesc_result;
#line 187

#line 187
  __nesc_result = HplMsp430Usart1P__Usart__isTxIntrPending();
#line 187

#line 187
  return __nesc_result;
#line 187
}
#line 187
# 339 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
static inline void HplMsp430Usart1P__Usart__disableTxIntr(void )
#line 339
{
  HplMsp430Usart1P__IE2 &= ~0x20;
}

# 178 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart.nc"
inline static void /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__disableTxIntr(void ){
#line 178
  HplMsp430Usart1P__Usart__disableTxIntr();
#line 178
}
#line 178
# 338 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static inline bool /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__isOwner(uint8_t id)
#line 338
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 339
    {
      unsigned char __nesc_temp = 
#line 339
      /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__resId == id && /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__state == /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__RES_BUSY;

      {
#line 339
        __nesc_atomic_end(__nesc_atomic); 
#line 339
        return __nesc_temp;
      }
    }
#line 341
    __nesc_atomic_end(__nesc_atomic); }
}

# 232 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline bool /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__default__isOwner(uint8_t id)
#line 232
{
#line 232
  return FALSE;
}

# 128 "/home/wtiberti/WSN/tinyos/tos/interfaces/Resource.nc"
inline static bool /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__isOwner(uint8_t arg_0x7f2557265ca0){
#line 128
  unsigned char __nesc_result;
#line 128

#line 128
  switch (arg_0x7f2557265ca0) {
#line 128
    case /*PlatformSerialC.UartC*/Msp430Uart1C__0__CLIENT_ID:
#line 128
      __nesc_result = /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__Resource__isOwner(/*PlatformSerialC.UartC.UsartC*/Msp430Usart1C__0__CLIENT_ID);
#line 128
      break;
#line 128
    default:
#line 128
      __nesc_result = /*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__default__isOwner(arg_0x7f2557265ca0);
#line 128
      break;
#line 128
    }
#line 128

#line 128
  return __nesc_result;
#line 128
}
#line 128
# 180 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static inline error_t /*Msp430Uart1P.UartP*/Msp430UartP__0__UartByte__send(uint8_t id, uint8_t data)
#line 180
{
  if (/*Msp430Uart1P.UartP*/Msp430UartP__0__UsartResource__isOwner(id) == FALSE) {
    return FAIL;
    }
#line 183
  /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__clrTxIntr();
  /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__disableTxIntr();
  /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__tx(data);
  while (!/*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__isTxIntrPending()) ;
  /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__clrTxIntr();
  /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__enableTxIntr();
  return SUCCESS;
}

# 50 "/home/wtiberti/WSN/tinyos/tos/interfaces/UartByte.nc"
inline static error_t SerialPrintfP__UartByte__send(uint8_t byte){
#line 50
  enum __nesc_unnamed4242 __nesc_result;
#line 50

#line 50
  __nesc_result = /*Msp430Uart1P.UartP*/Msp430UartP__0__UartByte__send(/*PlatformSerialC.UartC*/Msp430Uart1C__0__CLIENT_ID, byte);
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

# 367 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/clock_bcs/Msp430ClockP.nc"
static void Msp430ClockP__set_dco_calib(uint16_t calib)
#line 367
{
  BCSCTL1 = (BCSCTL1 & ~((0x01 | 0x02) | 0x04)) | ((calib >> 8) & ((0x01 | 0x02) | 0x04));
  DCOCTL = calib & 0xff;
}

# 16 "/home/wtiberti/WSN/tinyos/tos/platforms/telosb/MotePlatformC.nc"
static void MotePlatformC__TOSH_FLASH_M25P_DP_bit(bool set)
#line 16
{
  if (set) {
    TOSH_SET_SIMO0_PIN();
    }
  else {
#line 20
    TOSH_CLR_SIMO0_PIN();
    }
#line 21
  TOSH_SET_UCLK0_PIN();
  TOSH_CLR_UCLK0_PIN();
}

# 95 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static void /*HplMsp430GeneralIOC.P54*/HplMsp430GeneralIOP__36__IO__set(void )
#line 95
{
#line 95
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 95
    * (volatile uint8_t * )49U |= 0x01 << 4;
#line 95
    __nesc_atomic_end(__nesc_atomic); }
}

#line 95
static void /*HplMsp430GeneralIOC.P55*/HplMsp430GeneralIOP__37__IO__set(void )
#line 95
{
#line 95
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 95
    * (volatile uint8_t * )49U |= 0x01 << 5;
#line 95
    __nesc_atomic_end(__nesc_atomic); }
}

#line 95
static void /*HplMsp430GeneralIOC.P56*/HplMsp430GeneralIOP__38__IO__set(void )
#line 95
{
#line 95
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 95
    * (volatile uint8_t * )49U |= 0x01 << 6;
#line 95
    __nesc_atomic_end(__nesc_atomic); }
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
static void SchedulerBasicP__TaskBasic__runTask(uint8_t arg_0x7f2558a8f9c0){
#line 75
  switch (arg_0x7f2558a8f9c0) {
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
    case CC2420SpiP__grant:
#line 75
      CC2420SpiP__grant__runTask();
#line 75
      break;
#line 75
    case /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone_task:
#line 75
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone_task__runTask();
#line 75
      break;
#line 75
    case /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__grantedTask:
#line 75
      /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__grantedTask__runTask();
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
    case /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__grantedTask:
#line 75
      /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__grantedTask__runTask();
#line 75
      break;
#line 75
    default:
#line 75
      SchedulerBasicP__TaskBasic__default__runTask(arg_0x7f2558a8f9c0);
#line 75
      break;
#line 75
    }
#line 75
}
#line 75
# 88 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430UartP.nc"
static void /*Msp430Uart1P.UartP*/Msp430UartP__0__ResourceConfigure__configure(uint8_t id)
#line 88
{
  const msp430_uart_union_config_t *config = /*Msp430Uart1P.UartP*/Msp430UartP__0__Msp430UartConfigure__getConfig(id);

#line 90
  /*Msp430Uart1P.UartP*/Msp430UartP__0__m_byte_time = config->uartConfig.ubr / 2;
  if (!/*Msp430Uart1P.UartP*/Msp430UartP__0__m_byte_time) {
    /*Msp430Uart1P.UartP*/Msp430UartP__0__m_byte_time = 1;
    }
#line 93
  /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__setModeUart(config);
  /*Msp430Uart1P.UartP*/Msp430UartP__0__Usart__enableIntr();
}

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

# 283 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static error_t /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwner__release(void )
#line 283
{
  /* atomic removed: atomic calls only */
#line 284
  {
    if (/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId == /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__default_owner_id) {
        if (/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state == /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_GRANTING || /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state == /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_PREGRANT) {
            /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_GRANTING;
            /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__grantedTask__postTask();
            {
              enum __nesc_unnamed4242 __nesc_temp = 
#line 289
              SUCCESS;

#line 289
              return __nesc_temp;
            }
          }
        else {
#line 291
          if (/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state == /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_IMM_GRANTING) {
              /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__resId = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__reqResId;
              /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__reqResId = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__NO_RES;
              /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state = /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_BUSY;
              {
                enum __nesc_unnamed4242 __nesc_temp = 
#line 295
                SUCCESS;

#line 295
                return __nesc_temp;
              }
            }
          }
      }
  }
#line 299
  return FAIL;
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

# 251 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
static void HplMsp430Usart0P__Usart__setModeSpi(const msp430_spi_union_config_t *config)
#line 251
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 252
    {
      HplMsp430Usart0P__Usart__resetUsart(TRUE);
      HplMsp430Usart0P__HplI2C__clearModeI2C();
      HplMsp430Usart0P__Usart__disableUart();
      HplMsp430Usart0P__configSpi(config);
      HplMsp430Usart0P__Usart__enableSpi();
      HplMsp430Usart0P__Usart__resetUsart(FALSE);
      HplMsp430Usart0P__Usart__clrIntr();
      HplMsp430Usart0P__Usart__disableIntr();
    }
#line 261
    __nesc_atomic_end(__nesc_atomic); }
  return;
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

# 68 "/home/wtiberti/WSN/tinyos/tos/system/FcfsResourceQueueC.nc"
static resource_client_id_t /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__FcfsQueue__dequeue(void )
#line 68
{
  /* atomic removed: atomic calls only */
#line 69
  {
    if (/*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qHead != /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__NO_ENTRY) {
        uint8_t id = /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qHead;

#line 72
        /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qHead = /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__resQ[/*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qHead];
        if (/*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qHead == /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__NO_ENTRY) {
          /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__qTail = /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__NO_ENTRY;
          }
#line 75
        /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__resQ[id] = /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__NO_ENTRY;
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
      /*Msp430UsartShare0P.ArbiterC.Queue*/FcfsResourceQueueC__1__NO_ENTRY;

#line 78
      return __nesc_temp;
    }
  }
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

# 96 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static void /*HplMsp430GeneralIOC.P42*/HplMsp430GeneralIOP__26__IO__clr(void )
#line 96
{
#line 96
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 96
    * (volatile uint8_t * )29U &= ~(0x01 << 2);
#line 96
    __nesc_atomic_end(__nesc_atomic); }
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

# 134 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/Msp430SpiNoDmaP.nc"
static uint8_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiByte__write(uint8_t tx)
#line 134
{
  uint8_t byte;


  /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__tx(tx);
  while (!/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__isRxIntrPending()) ;
  /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__clrRxIntr();
  byte = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__rx();

  return byte;
}

#line 205
static error_t /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SpiPacket__send(uint8_t id, uint8_t *tx_buf, 
uint8_t *rx_buf, 
uint16_t len)
#line 207
{

  /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_client = id;
  /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_tx_buf = tx_buf;
  /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_rx_buf = rx_buf;
  /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_len = len;
  /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_pos = 0;

  if (len) {
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__enableRxIntr();
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__continueOp();
    }
  else {
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__signalDone_task__postTask();
    }

  return SUCCESS;
}

#line 182
static void /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__continueOp(void )
#line 182
{

  uint8_t end;
  uint8_t tmp;

  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 187
    {
      /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__tx(/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_tx_buf ? /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_tx_buf[/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_pos] : 0);

      end = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_pos + /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__SPI_ATOMIC_SIZE;
      if (end > /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_len) {
        end = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_len;
        }
      while (++/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_pos < end) {
          while (!/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__isRxIntrPending()) ;
          tmp = /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__rx();
          if (/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_rx_buf) {
            /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_rx_buf[/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_pos - 1] = tmp;
            }
#line 199
          /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__Usart__tx(/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_tx_buf ? /*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_tx_buf[/*Msp430SpiNoDma0P.SpiP*/Msp430SpiNoDmaP__0__m_pos] : 0);
        }
    }
#line 201
    __nesc_atomic_end(__nesc_atomic); }
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

# 96 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static void /*HplMsp430GeneralIOC.P54*/HplMsp430GeneralIOP__36__IO__clr(void )
#line 96
{
#line 96
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 96
    * (volatile uint8_t * )49U &= ~(0x01 << 4);
#line 96
    __nesc_atomic_end(__nesc_atomic); }
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

# 233 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
static void HplMsp430Usart0P__Usart__disableSpi(void )
#line 233
{
  /* atomic removed: atomic calls only */
#line 234
  {
    HplMsp430Usart0P__ME1 &= ~0x40;
    HplMsp430Usart0P__SIMO__selectIOFunc();
    HplMsp430Usart0P__SOMI__selectIOFunc();
    HplMsp430Usart0P__UCLK__selectIOFunc();
  }
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

# 95 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static void /*HplMsp430GeneralIOC.P42*/HplMsp430GeneralIOP__26__IO__set(void )
#line 95
{
#line 95
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 95
    * (volatile uint8_t * )29U |= 0x01 << 2;
#line 95
    __nesc_atomic_end(__nesc_atomic); }
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
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Alarm__startAt(/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type t0, /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type dt)
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_t0 = t0;
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_dt = dt;
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__set_alarm();
    }
#line 154
    __nesc_atomic_end(__nesc_atomic); }
}

#line 107
static void /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__set_alarm(void )
{
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type now = /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__Counter__get();
#line 109
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type expires;
#line 109
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type remaining;




  expires = /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_t0 + /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_dt;


  remaining = (/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__to_size_type )(expires - now);


  if (/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_t0 <= now) 
    {
      if (expires >= /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_t0 && 
      expires <= now) {
        remaining = 0;
        }
    }
  else {
      if (expires >= /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_t0 || 
      expires <= now) {
        remaining = 0;
        }
    }
#line 132
  if (remaining > /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__MAX_DELAY) 
    {
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_t0 = now + /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__MAX_DELAY;
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_dt = remaining - /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__MAX_DELAY;
      remaining = /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__MAX_DELAY;
    }
  else 
    {
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_t0 += /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_dt;
      /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__m_dt = 0;
    }
  /*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__AlarmFrom__startAt((/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__from_size_type )now << 0, 
  (/*AlarmMultiplexC.Alarm.Alarm32khz32C.Transform*/TransformAlarmC__1__from_size_type )remaining << 0);
}

# 80 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
static /*Counter32khz32C.Transform*/TransformCounterC__1__to_size_type /*Counter32khz32C.Transform*/TransformCounterC__1__Counter__get(void )
{
  /*Counter32khz32C.Transform*/TransformCounterC__1__to_size_type rv = 0;

#line 83
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      /*Counter32khz32C.Transform*/TransformCounterC__1__upper_count_type high = /*Counter32khz32C.Transform*/TransformCounterC__1__m_upper;
      /*Counter32khz32C.Transform*/TransformCounterC__1__from_size_type low = /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__get();

#line 87
      if (/*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__isOverflowPending()) 
        {






          high++;
          low = /*Counter32khz32C.Transform*/TransformCounterC__1__CounterFrom__get();
        }
      {
        /*Counter32khz32C.Transform*/TransformCounterC__1__to_size_type high_to = high;
        /*Counter32khz32C.Transform*/TransformCounterC__1__to_size_type low_to = low >> /*Counter32khz32C.Transform*/TransformCounterC__1__LOW_SHIFT_RIGHT;

#line 101
        rv = (high_to << /*Counter32khz32C.Transform*/TransformCounterC__1__HIGH_SHIFT_LEFT) | low_to;
      }
    }
#line 103
    __nesc_atomic_end(__nesc_atomic); }
  return rv;
}

# 64 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
static uint16_t /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Timer__get(void )
{




  if (1) {
      /* atomic removed: atomic calls only */
#line 71
      {
        uint16_t t0;
        uint16_t t1 = * (volatile uint16_t * )400U;

#line 74
        do {
#line 74
            t0 = t1;
#line 74
            t1 = * (volatile uint16_t * )400U;
          }
        while (
#line 74
        t0 != t1);
        {
          unsigned short __nesc_temp = 
#line 75
          t1;

#line 75
          return __nesc_temp;
        }
      }
    }
  else 
#line 78
    {
      return * (volatile uint16_t * )400U;
    }
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

# 96 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/pins/HplMsp430GeneralIOP.nc"
static void /*HplMsp430GeneralIOC.P46*/HplMsp430GeneralIOP__30__IO__clr(void )
#line 96
{
#line 96
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 96
    * (volatile uint8_t * )29U &= ~(0x01 << 6);
#line 96
    __nesc_atomic_end(__nesc_atomic); }
}

#line 95
static void /*HplMsp430GeneralIOC.P46*/HplMsp430GeneralIOP__30__IO__set(void )
#line 95
{
#line 95
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
#line 95
    * (volatile uint8_t * )29U |= 0x01 << 6;
#line 95
    __nesc_atomic_end(__nesc_atomic); }
}

# 56 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/GpioCaptureC.nc"
static error_t /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__enableCapture(uint8_t mode)
#line 56
{
  /* atomic removed: atomic calls only */
#line 57
  {
    /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__disableEvents();
    /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__GeneralIO__makeInput();
    /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__GeneralIO__selectModuleFunc();







    /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__setControlAsCapture(mode, MSP430TIMER_CCI_A);
    /*HplCC2420InterruptsC.CaptureSFDC*/GpioCaptureC__0__Msp430TimerControl__enableEvents();
  }
  return SUCCESS;
}

# 80 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformCounterC.nc"
static /*CounterMilli32C.Transform*/TransformCounterC__0__to_size_type /*CounterMilli32C.Transform*/TransformCounterC__0__Counter__get(void )
{
  /*CounterMilli32C.Transform*/TransformCounterC__0__to_size_type rv = 0;

#line 83
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      /*CounterMilli32C.Transform*/TransformCounterC__0__upper_count_type high = /*CounterMilli32C.Transform*/TransformCounterC__0__m_upper;
      /*CounterMilli32C.Transform*/TransformCounterC__0__from_size_type low = /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__get();

#line 87
      if (/*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__isOverflowPending()) 
        {






          high++;
          low = /*CounterMilli32C.Transform*/TransformCounterC__0__CounterFrom__get();
        }
      {
        /*CounterMilli32C.Transform*/TransformCounterC__0__to_size_type high_to = high;
        /*CounterMilli32C.Transform*/TransformCounterC__0__to_size_type low_to = low >> /*CounterMilli32C.Transform*/TransformCounterC__0__LOW_SHIFT_RIGHT;

#line 101
        rv = (high_to << /*CounterMilli32C.Transform*/TransformCounterC__0__HIGH_SHIFT_LEFT) | low_to;
      }
    }
#line 103
    __nesc_atomic_end(__nesc_atomic); }
  return rv;
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

# 147 "/home/wtiberti/WSN/tinyos/tos/lib/timer/TransformAlarmC.nc"
static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Alarm__startAt(/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type t0, /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type dt)
{
  { __nesc_atomic_t __nesc_atomic = __nesc_atomic_start();
    {
      /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_t0 = t0;
      /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_dt = dt;
      /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__set_alarm();
    }
#line 154
    __nesc_atomic_end(__nesc_atomic); }
}

#line 107
static void /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__set_alarm(void )
{
  /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type now = /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__Counter__get();
#line 109
  /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type expires;
#line 109
  /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type remaining;




  expires = /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_t0 + /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_dt;


  remaining = (/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__to_size_type )(expires - now);


  if (/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_t0 <= now) 
    {
      if (expires >= /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_t0 && 
      expires <= now) {
        remaining = 0;
        }
    }
  else {
      if (expires >= /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_t0 || 
      expires <= now) {
        remaining = 0;
        }
    }
#line 132
  if (remaining > /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__MAX_DELAY) 
    {
      /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_t0 = now + /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__MAX_DELAY;
      /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_dt = remaining - /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__MAX_DELAY;
      remaining = /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__MAX_DELAY;
    }
  else 
    {
      /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_t0 += /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_dt;
      /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__m_dt = 0;
    }
  /*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__AlarmFrom__startAt((/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__from_size_type )now << 5, 
  (/*HilTimerMilliC.AlarmMilli32C.Transform*/TransformAlarmC__0__from_size_type )remaining << 5);
}

# 17 "/home/wtiberti/WSN/tinyos/tos/chips/ds2411/LocalIeeeEui64P.nc"
static ieee_eui64_t LocalIeeeEui64P__LocalIeeeEui64__getId(void )
#line 17
{
  uint8_t buf[6] = { 0 };
  error_t e;

  if (!LocalIeeeEui64P__have_id) {
      e = LocalIeeeEui64P__ReadId48__read(buf);
      if (e == SUCCESS) {
          LocalIeeeEui64P__eui.data[0] = IEEE_EUI64_COMPANY_ID_0;
          LocalIeeeEui64P__eui.data[1] = IEEE_EUI64_COMPANY_ID_1;
          LocalIeeeEui64P__eui.data[2] = IEEE_EUI64_COMPANY_ID_2;



          LocalIeeeEui64P__eui.data[3] = IEEE_EUI64_SERIAL_ID_0;
          LocalIeeeEui64P__eui.data[4] = IEEE_EUI64_SERIAL_ID_1;


          LocalIeeeEui64P__eui.data[5] = buf[2];
          LocalIeeeEui64P__eui.data[6] = buf[1];
          LocalIeeeEui64P__eui.data[7] = buf[0];

          LocalIeeeEui64P__have_id = TRUE;
        }
    }
  return LocalIeeeEui64P__eui;
}

# 64 "/home/wtiberti/WSN/tinyos/tos/lib/timer/BusyWaitCounterC.nc"
static void /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__BusyWait__wait(/*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__size_type dt)
{
  /* atomic removed: atomic calls only */
  {



    /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__size_type t0 = /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__get();

    if (dt > /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__HALF_MAX_SIZE_TYPE) 
      {
        dt -= /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__HALF_MAX_SIZE_TYPE;
        while ((/*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__size_type )(/*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__get() - t0) <= dt) ;
        t0 += dt;
        dt = /*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__HALF_MAX_SIZE_TYPE;
      }

    while ((/*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__size_type )(/*BusyWaitMicroC.BusyWaitCounterC*/BusyWaitCounterC__0__Counter__get() - t0) <= dt) ;
  }
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

# 11 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/timer/Msp430TimerCommonP.nc"
__attribute((wakeup)) __attribute((interrupt(7)))  void sig_TIMERA0_VECTOR(void )
#line 11
{
#line 11
  Msp430TimerCommonP__VectorTimerA0__fired();
}

# 160 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerCapComP.nc"
static void /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Event__fired(void )
#line 160
{
  if (/*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Control__getControl().cap) {
    /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Capture__captured(/*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Capture__getEvent());
    }
  else {
#line 164
    /*Msp430TimerC.Msp430TimerA0*/Msp430TimerCapComP__0__Compare__fired();
    }
}

#line 160
static void /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Event__fired(void )
#line 160
{
  if (/*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Control__getControl().cap) {
    /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Capture__captured(/*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Capture__getEvent());
    }
  else {
#line 164
    /*Msp430TimerC.Msp430TimerA1*/Msp430TimerCapComP__1__Compare__fired();
    }
}

#line 160
static void /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Event__fired(void )
#line 160
{
  if (/*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Control__getControl().cap) {
    /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Capture__captured(/*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Capture__getEvent());
    }
  else {
#line 164
    /*Msp430TimerC.Msp430TimerA2*/Msp430TimerCapComP__2__Compare__fired();
    }
}

# 12 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/timer/Msp430TimerCommonP.nc"
__attribute((wakeup)) __attribute((interrupt(6)))  void sig_TIMERA1_VECTOR(void )
#line 12
{
#line 12
  Msp430TimerCommonP__VectorTimerA1__fired();
}

#line 13
__attribute((wakeup)) __attribute((interrupt(14)))  void sig_TIMERB0_VECTOR(void )
#line 13
{
#line 13
  Msp430TimerCommonP__VectorTimerB0__fired();
}

# 168 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerP.nc"
static void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Event__default__fired(uint8_t n)
#line 168
{
}

# 39 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/timer/Msp430TimerEvent.nc"
static void /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Event__fired(uint8_t arg_0x7f25584338b0){
#line 39
  switch (arg_0x7f25584338b0) {
#line 39
    case 0:
#line 39
      /*Msp430TimerC.Msp430TimerB0*/Msp430TimerCapComP__3__Event__fired();
#line 39
      break;
#line 39
    case 1:
#line 39
      /*Msp430TimerC.Msp430TimerB1*/Msp430TimerCapComP__4__Event__fired();
#line 39
      break;
#line 39
    case 2:
#line 39
      /*Msp430TimerC.Msp430TimerB2*/Msp430TimerCapComP__5__Event__fired();
#line 39
      break;
#line 39
    case 3:
#line 39
      /*Msp430TimerC.Msp430TimerB3*/Msp430TimerCapComP__6__Event__fired();
#line 39
      break;
#line 39
    case 4:
#line 39
      /*Msp430TimerC.Msp430TimerB4*/Msp430TimerCapComP__7__Event__fired();
#line 39
      break;
#line 39
    case 5:
#line 39
      /*Msp430TimerC.Msp430TimerB5*/Msp430TimerCapComP__8__Event__fired();
#line 39
      break;
#line 39
    case 6:
#line 39
      /*Msp430TimerC.Msp430TimerB6*/Msp430TimerCapComP__9__Event__fired();
#line 39
      break;
#line 39
    case 7:
#line 39
      /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Overflow__fired();
#line 39
      break;
#line 39
    default:
#line 39
      /*Msp430TimerC.Msp430TimerB*/Msp430TimerP__1__Event__default__fired(arg_0x7f25584338b0);
#line 39
      break;
#line 39
    }
#line 39
}
#line 39
# 14 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/timer/Msp430TimerCommonP.nc"
__attribute((wakeup)) __attribute((interrupt(13)))  void sig_TIMERB1_VECTOR(void )
#line 14
{
#line 14
  Msp430TimerCommonP__VectorTimerB1__fired();
}

# 78 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/x1x2/pins/HplMsp430InterruptP.nc"
__attribute((wakeup)) __attribute((interrupt(5)))  void sig_PORT1_VECTOR(void )
#line 78
{
  volatile uint8_t n = P1IFG & P1IE;

#line 96
  if (n & (1 << 0)) {
#line 96
      HplMsp430InterruptP__Port10__clear();
#line 96
      HplMsp430InterruptP__Port10__fired();
#line 96
      return;
    }
#line 97
  if (n & (1 << 1)) {
#line 97
      HplMsp430InterruptP__Port11__clear();
#line 97
      HplMsp430InterruptP__Port11__fired();
#line 97
      return;
    }
#line 98
  if (n & (1 << 2)) {
#line 98
      HplMsp430InterruptP__Port12__clear();
#line 98
      HplMsp430InterruptP__Port12__fired();
#line 98
      return;
    }
#line 99
  if (n & (1 << 3)) {
#line 99
      HplMsp430InterruptP__Port13__clear();
#line 99
      HplMsp430InterruptP__Port13__fired();
#line 99
      return;
    }
#line 100
  if (n & (1 << 4)) {
#line 100
      HplMsp430InterruptP__Port14__clear();
#line 100
      HplMsp430InterruptP__Port14__fired();
#line 100
      return;
    }
#line 101
  if (n & (1 << 5)) {
#line 101
      HplMsp430InterruptP__Port15__clear();
#line 101
      HplMsp430InterruptP__Port15__fired();
#line 101
      return;
    }
#line 102
  if (n & (1 << 6)) {
#line 102
      HplMsp430InterruptP__Port16__clear();
#line 102
      HplMsp430InterruptP__Port16__fired();
#line 102
      return;
    }
#line 103
  if (n & (1 << 7)) {
#line 103
      HplMsp430InterruptP__Port17__clear();
#line 103
      HplMsp430InterruptP__Port17__fired();
#line 103
      return;
    }
}

#line 227
__attribute((wakeup)) __attribute((interrupt(2)))  void sig_PORT2_VECTOR(void )
#line 227
{
  volatile uint8_t n = P2IFG & P2IE;

  if (n & (1 << 0)) {
#line 230
      HplMsp430InterruptP__Port20__clear();
#line 230
      HplMsp430InterruptP__Port20__fired();
#line 230
      return;
    }
#line 231
  if (n & (1 << 1)) {
#line 231
      HplMsp430InterruptP__Port21__clear();
#line 231
      HplMsp430InterruptP__Port21__fired();
#line 231
      return;
    }
#line 232
  if (n & (1 << 2)) {
#line 232
      HplMsp430InterruptP__Port22__clear();
#line 232
      HplMsp430InterruptP__Port22__fired();
#line 232
      return;
    }
#line 233
  if (n & (1 << 3)) {
#line 233
      HplMsp430InterruptP__Port23__clear();
#line 233
      HplMsp430InterruptP__Port23__fired();
#line 233
      return;
    }
#line 234
  if (n & (1 << 4)) {
#line 234
      HplMsp430InterruptP__Port24__clear();
#line 234
      HplMsp430InterruptP__Port24__fired();
#line 234
      return;
    }
#line 235
  if (n & (1 << 5)) {
#line 235
      HplMsp430InterruptP__Port25__clear();
#line 235
      HplMsp430InterruptP__Port25__fired();
#line 235
      return;
    }
#line 236
  if (n & (1 << 6)) {
#line 236
      HplMsp430InterruptP__Port26__clear();
#line 236
      HplMsp430InterruptP__Port26__fired();
#line 236
      return;
    }
#line 237
  if (n & (1 << 7)) {
#line 237
      HplMsp430InterruptP__Port27__clear();
#line 237
      HplMsp430InterruptP__Port27__fired();
#line 237
      return;
    }
}

# 82 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
__attribute((wakeup)) __attribute((interrupt(10)))  void sig_USART0RX_VECTOR(void )
#line 82
{
  uint8_t temp = U0RXBUF;

#line 84
  HplMsp430Usart0P__Interrupts__rxDone(temp);
}

# 307 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static bool /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ArbiterInfo__inUse(void )
#line 307
{
  /* atomic removed: atomic calls only */
#line 308
  {
    if (/*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__state == /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__RES_DEF_OWNED) 
      {
        unsigned char __nesc_temp = 
#line 310
        /*Msp430UsartShare0P.ArbiterC.Arbiter*/ArbiterP__0__ResourceDefaultOwnerInfo__inUse();

#line 310
        return __nesc_temp;
      }
#line 311
    {
      unsigned char __nesc_temp = 
#line 311
      TRUE;

#line 311
      return __nesc_temp;
    }
  }
}

# 87 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart0P.nc"
__attribute((wakeup)) __attribute((interrupt(9)))  void sig_USART0TX_VECTOR(void )
#line 87
{
  if (HplMsp430Usart0P__HplI2C__isI2C()) {
    HplMsp430Usart0P__I2CInterrupts__fired();
    }
  else {
#line 91
    HplMsp430Usart0P__Interrupts__txDone();
    }
}

# 64 "/home/wtiberti/WSN/tinyos/tos/lib/printf/SerialPrintfP.nc"
  int printfflush(void )
#line 64
{
  return SUCCESS;
}

# 82 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
__attribute((wakeup)) __attribute((interrupt(4)))  void sig_USART1RX_VECTOR(void )
#line 82
{
  uint8_t temp = U1RXBUF;

#line 84
  HplMsp430Usart1P__Interrupts__rxDone(temp);
}

# 307 "/home/wtiberti/WSN/tinyos/tos/system/ArbiterP.nc"
static bool /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ArbiterInfo__inUse(void )
#line 307
{
  /* atomic removed: atomic calls only */
#line 308
  {
    if (/*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__state == /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__RES_DEF_OWNED) 
      {
        unsigned char __nesc_temp = 
#line 310
        /*Msp430UsartShare1P.ArbiterC.Arbiter*/ArbiterP__1__ResourceDefaultOwnerInfo__inUse();

#line 310
        return __nesc_temp;
      }
#line 311
    {
      unsigned char __nesc_temp = 
#line 311
      TRUE;

#line 311
      return __nesc_temp;
    }
  }
}

# 87 "/home/wtiberti/WSN/tinyos/tos/chips/msp430/usart/HplMsp430Usart1P.nc"
__attribute((wakeup)) __attribute((interrupt(3)))  void sig_USART1TX_VECTOR(void )
#line 87
{
  HplMsp430Usart1P__Interrupts__txDone();
}

# 107 "/home/wtiberti/WSN/tinyos/tos/lib/printf/PutcharP.nc"
__attribute((noinline))   int putchar(int c)
#line 107
{
#line 119
  return PutcharP__Putchar__putchar(c);
}

