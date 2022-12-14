#pragma once

namespace NT
{
enum CREATE_DISPOSITION {
    FILE_SUPERSEDE,
    FILE_OPEN,
    FILE_CREATE,
    FILE_OPEN_IF,
    FILE_OVERWRITE,
    FILE_OVERWRITE_IF
};
}