/* Copyright (c) 2015, Robert Escriva
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of this project nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* C */
#include <assert.h>
#include <limits.h>
#include <math.h>
#include <string.h>

/* POSIX */
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

/* popt */
#include <popt.h>

/* redupe */
#include <redupe.h>

#define BUF_SIZE 4096

static int
encode_stream(FILE *input, struct redupe_encode_file *output, int64_t block_size)
{
    unsigned char buf[BUF_SIZE];

    while (1)
    {
        size_t amt = fread(buf, 1, BUF_SIZE, input);

        if (ferror(input))
        {
            fprintf(stderr, "error reading input\n");
            return EXIT_FAILURE;
        }

        if (amt == 0)
        {
            break;
        }

        assert(amt > 0);
        ssize_t written = redupe_encode_write(output, buf, amt, block_size);

        if (written != (ssize_t)amt)
        {
            fprintf(stderr, "error writing output\n");
            return EXIT_FAILURE;
        }

        if (feof(input))
        {
            break;
        }
    }

    return EXIT_SUCCESS;
}

static int
encode_file(const char *file, unsigned code_sz, int64_t block_size)
{
    FILE* input = fopen(file, "r");

    if (!input)
    {
        fprintf(stderr, "error opening %s\n", file);
        return EXIT_FAILURE;
    }

    char path[PATH_MAX];
    strncpy(path, file, PATH_MAX);

    if (strnlen(path, PATH_MAX) >= PATH_MAX - 4)
    {
        fprintf(stderr, "pathname too long\n");
        fclose(input);
        return EXIT_FAILURE;
    }

    strcat(path, ".rd");
    struct redupe_encode_file* output = redupe_encode_open(path, code_sz, block_size);

    if (!output)
    {
        fprintf(stderr, "could not open output\n");
        fclose(input);
        return EXIT_FAILURE;
    }

    int ret = encode_stream(input, output, block_size);
    fclose(input);

    if (redupe_encode_close(output, block_size) < 0)
    {
        fprintf(stderr, "could not flush output\n");
        return EXIT_FAILURE;
    }

    return ret;
}

static int
correct_stream(struct redupe_correct_file *input, FILE *output, int64_t block_size)
{
    unsigned char buf[BUF_SIZE];

    while (1)
    {
        ssize_t amt = redupe_correct_read(input, buf, BUF_SIZE, block_size);

        if (amt < 0)
        {
            fprintf(stderr, "error reading input\n");
            return EXIT_FAILURE;
        }
        else if (amt == 0)
        {
            break;
        }

        size_t written = fwrite(buf, 1, amt, output);

        if (written != (size_t)amt)
        {
            fprintf(stderr, "error writing output\n");
            return EXIT_FAILURE;
        }
    }

    if (fflush(output) != 0)
    {
        fprintf(stderr, "error flushing output: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    fsync(fileno(output));
    return EXIT_SUCCESS;
}

static int
correct_file(const char *file, int64_t block_size)
{
    size_t file_sz = strlen(file);

    if (file_sz < 4 ||
        strcmp(file + file_sz - 3, ".rd") != 0)
    {
        fprintf(stderr, "cannot correct file unless it ends in .rd\n");
        return EXIT_FAILURE;
    }

    char* buf = malloc(2 * file_sz + 9);

    if (!buf)
    {
        fprintf(stderr, "error allocating memory\n");
        return EXIT_FAILURE;
    }

    char* newpath = buf;
    memmove(newpath, file, file_sz + 1);
    char* tmpfile = buf + file_sz - 2;
    *(tmpfile - 1) = '\0';
    *tmpfile = '.';
    memmove(tmpfile + 1, file, file_sz + 1);
    memmove(tmpfile + 1 + file_sz, ".XXXXXX", 7);
    struct stat stbuf;

    if (stat(newpath, &stbuf) == 0)
    {
        free(buf);
        fprintf(stderr, "will not overwrite %s\n", newpath);
        return EXIT_FAILURE;
    }

    if (mkstemp(tmpfile) < 0)
    {
        free(buf);
        fprintf(stderr, "error creating temporary file\n");
        return EXIT_FAILURE;
    }

    struct redupe_correct_file* input = redupe_correct_open(file, block_size);

    if (!input)
    {
        free(buf);
        fprintf(stderr, "error opening input %s\n", file);
        return EXIT_FAILURE;
    }

    FILE* tmp = fopen(tmpfile, "w+");

    if (!tmp)
    {
        redupe_correct_close(input);
        free(buf);
        fprintf(stderr, "error opening temporary output %s\n", tmpfile);
        return EXIT_FAILURE;
    }

    int x = correct_stream(input, tmp, block_size);
    redupe_correct_close(input);
    fclose(tmp);

    if (x == EXIT_SUCCESS)
    {
        if (rename(tmpfile, newpath) < 0)
        {
            fprintf(stderr, "error moving temporary file %s to %s\n", tmpfile, newpath);
            x = EXIT_FAILURE;
        }
    }
    else
    {
        unlink(tmpfile);
    }

    free(buf);
    return x;
}

int64_t parce_block_size(char * input)
{
    int64_t block_size = 0;

    // @todo: consider to implement some %s limit during reading

    char * multiplier = malloc(sizeof(char) * strlen(input));
    sscanf(input,"%ld%s", &block_size, multiplier);
    int mul = 1;

    if (!strcmp(multiplier, "M"))
    {
        mul = 1024;
    }
    else if(!strcmp(multiplier, "MB"))
    {
        mul = 1000;
    }
    else if(!strcmp(multiplier, "G"))
    {
        mul =  1024 * 1024;
    }
    else if(!strcmp(multiplier, "GB"))
    {
        mul =  1000 * 1000;
    }
    else if (strlen(multiplier))
    {
        // error: only no multiplier or Mx or Gx is allowed
        free(multiplier);
        return -1;
    }
    free(multiplier);
    return block_size * mul;
}

int
main(int argc, const char* argv[])
{
    int rc;

    int encode = 0;
    int decode = 0;
    char * block_size_str = NULL;
    int64_t block_size = 4096*255;
    double overhead = 12.549;
    struct poptOption redupe_args[] = {
        POPT_AUTOHELP
        {"encode", 'e', POPT_ARG_NONE, &encode, 0, "Encode file or stream", ""},
        {"decode", 'd', POPT_ARG_NONE, &decode, 0, "Decode file or stream", ""},
        {"block-size", 'b', POPT_ARG_STRING, &block_size_str, 0, \
            "Block size may be followed by the following multiplicative suffixes: M=1000, MB=1024, "
            "G=1000*1000, GB=1024*1024 (default 1 044 480 bytes)", ""},
        {"overhead", 'o', POPT_ARG_DOUBLE, &overhead, 0, "overhead as a % (default 12.5%)", "0-100"},
        POPT_TABLEEND
    };

    poptContext ctx;
    ctx = poptGetContext(NULL, argc, argv, redupe_args,
                         POPT_CONTEXT_POSIXMEHARDER);

    while ((rc = poptGetNextOpt(ctx)) != -1)
    {
        if (rc <= 0)
        {
            switch (rc)
            {
                case POPT_ERROR_NOARG:
                case POPT_ERROR_BADOPT:
                case POPT_ERROR_BADNUMBER:
                case POPT_ERROR_OVERFLOW:
                    fprintf(stderr, "%s %s\n", poptStrerror(rc), poptBadOption(ctx, 0));
                    poptPrintUsage(ctx, stderr, 0);
                    return EXIT_FAILURE;
                case POPT_ERROR_OPTSTOODEEP:
                case POPT_ERROR_BADQUOTE:
                case POPT_ERROR_ERRNO:
                default:
                    fprintf(stderr, "logic error in argument parsing\n");
                    poptPrintUsage(ctx, stderr, 0);
                    return EXIT_FAILURE;
            }

            continue;
        }
    }

    if (!(encode || decode))
    {
        fprintf(stderr, "encode or decode operation must be specified\n");
        poptPrintUsage(ctx, stderr, 0);
        return EXIT_FAILURE;
    }
    if (encode && decode)
    {
        fprintf(stderr, "Only encode or decode operation must be specified, not both\n");
        poptPrintUsage(ctx, stderr, 0);
        return EXIT_FAILURE;
    }

    if (overhead < 1 || overhead >= 95)
    {
        fprintf(stderr, "overhead %% must be in the range [1, 95)\n");
        poptPrintUsage(ctx, stderr, 0);
        return EXIT_FAILURE;
    }

    if (block_size_str)
    {
        block_size = parce_block_size(block_size_str);

        if (block_size < 0)
        {
            fprintf(stderr, "Only non-multiplier or Mx or Gx is allowed\n");
            poptPrintUsage(ctx, stderr, 0);
            return EXIT_FAILURE;
        }
    }

    block_size = ceil((double)block_size / 255);

    unsigned code_sz = 32;
    unsigned msg_sz = 223;
    code_sz = ceil(2.55 * overhead);
    msg_sz = 255 - code_sz;
    assert(code_sz < 255);
    assert(code_sz > 0);
    assert(msg_sz <= 255);
    assert(msg_sz > 0);

    const char** args = poptGetArgs(ctx);
    int ret = EXIT_SUCCESS;

    if (!args || !*args)
    {
        if (decode)
        {
            struct redupe_correct_file* input = redupe_correct_from_file(stdin, block_size);

            if (!input)
            {
                fprintf(stderr, "error allocating memory\n");
                ret = EXIT_FAILURE;
            }
            else
            {
                ret = correct_stream(input, stdout, block_size);

                if (redupe_correct_close(input) < 0)
                {
                    fprintf(stderr, "error reading input\n");
                    ret = EXIT_FAILURE;
                }
            }
        }
        else
        {
            struct redupe_encode_file* output = redupe_encode_from_file(stdout, code_sz, block_size);

            if (!output)
            {
                fprintf(stderr, "error allocating memory\n");
                ret = EXIT_FAILURE;
            }
            else
            {
                ret = encode_stream(stdin, output, block_size);

                if (redupe_encode_close(output, block_size) < 0)
                {
                    fprintf(stderr, "error reading output\n");
                    ret = EXIT_FAILURE;
                }
            }
        }
    }
    else
    {
        for (; *args; ++args)
        {
            int x = 0;

            if (decode)
            {
                x = correct_file(*args, block_size);
            }
            else
            {
                x = encode_file(*args, code_sz, block_size);
            }

            if (x != EXIT_SUCCESS && ret == EXIT_SUCCESS)
            {
                ret = x;
            }
        }
    }

    poptFreeContext(ctx);
    return ret;
}
