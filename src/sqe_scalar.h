#pragma once

#define PREP_SQE(sqe, tmpl, fd_val, ud_val) do { \
    *(sqe) = (tmpl);                              \
    (sqe)->fd = (fd_val);                         \
    (sqe)->user_data = (ud_val);                  \
} while (0)

// 5-field variant for file I/O: struct copy + patch fd, off, addr, len, user_data
#define PREP_SQE_FILE(sqe, tmpl, fd_val, off_val, addr_val, len_val, ud_val) do { \
    *(sqe) = (tmpl);                                                               \
    (sqe)->fd        = (fd_val);                                                   \
    (sqe)->off       = (off_val);                                                  \
    (sqe)->addr      = (addr_val);                                                 \
    (sqe)->len       = (len_val);                                                  \
    (sqe)->user_data = (ud_val);                                                   \
} while (0)
