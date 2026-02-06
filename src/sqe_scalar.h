#pragma once

#define PREP_SQE(sqe, tmpl, fd_val, ud_val) do { \
    *(sqe) = (tmpl);                              \
    (sqe)->fd = (fd_val);                         \
    (sqe)->user_data = (ud_val);                  \
} while (0)
