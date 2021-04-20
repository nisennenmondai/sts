/* 
 *  Info  - Generally useful information to log (service start/stop, 
 *          configuration assumptions, etc). Info I want to always have 
 *          available but usually don't care about under normal circumstances. 
 *          This is my out-of-the-box config level.
 *
 *  Warn  - Anything that can potentially cause application oddities, but for 
 *          which I am automatically recovering. (Such as switching from a 
 *          primary to backup server, retrying an operation, missing secondary 
 *          data, etc.)
 *
 *  Trace - Only when I would be "tracing" the code and trying to find one part 
 *          of a function specifically.
 *
 *  Debug - Information that is diagnostically helpful to people more than just 
 *          developers (IT, sysadmins, etc.).
 *
 *  Error - Any error which is fatal to the operation, but not the service or 
 *          application (can't open a required file, missing data, etc.). These 
 *          errors will force user (administrator, or direct user) intervention. 
 *          These are usually reserved (in my apps) for incorrect connection 
 *          strings, missing services, etc.
 *
 *  Fatal - Any error that is forcing a shutdown of the service or application 
 *          to prevent data loss (or further data loss). I reserve these only 
 *          for the most heinous errors and situations where there is guaranteed 
 *          to have been data corruption or loss.
 *
 *  Tests - For tests 
 */
#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

#define FMT_INFO  " - [INFO]  # "
#define FMT_WARN  " - [WARN]  # "
#define FMT_TRACE " - [TRACE] # "
#define FMT_DEBUG " - [DEBUG] # "
#define FMT_ERROR " - [ERROR] # "
#define FMT_FATAL " - [FATAL] # "
#define FMT_TESTS " - [TESTS] # "

#define INFO(...)  print(FMT_INFO  __VA_ARGS__) 
#define WARN(...)  print(FMT_WARN  __VA_ARGS__) 
#define TRACE(...) print(FMT_TRACE __VA_ARGS__) 
#define DEBUG(...) print(FMT_DEBUG __VA_ARGS__) 
#define ERROR(...) print(FMT_ERROR __VA_ARGS__) 
#define FATAL(...) print(FMT_FATAL __VA_ARGS__) 
#define TESTS(...) print(FMT_TESTS __VA_ARGS__) 

#define BUFFSIZE 25
#define MSSIZE   7

static void concatenate(char p[], char q[]) {
        int c;
        int d;
        c = 0;

        while (p[c] != '\0') {
                c++;
        }
        d = 0;

        while (q[d] != '\0') {
                p[c] = q[d];
                d++;
                c++;
        }
        p[c] = '\0';
}

static void print(const char *message, ...)
{
        char buffer[BUFFSIZE];
        char ms[MSSIZE];
        unsigned int millisec;
        va_list args;
        struct timeval tv;
        struct tm* tm_info;

        va_start(args, message);    

        gettimeofday(&tv, NULL);

        /* round to nearest millisec */
        millisec = lrint(tv.tv_usec/1000.0);
        /* allow for rounding up to nearest second */
        if (millisec>=1000) { 
                millisec -=1000;
                tv.tv_sec++;
        }
        tm_info = localtime(&tv.tv_sec);
        sprintf(ms, "%03d", millisec);
        strftime(buffer, 25, "%Y-%m-%d %H:%M:%S.", tm_info);

        concatenate(buffer, ms);
        printf("%s", buffer);

        vprintf(message, args);
        va_end(args);
}
#endif /* LOG_H */
