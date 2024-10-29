OHRE_HAP_ROOT_WHITE = {
    ".": ["pack.info", "module.json", "resources.index"]
}

OHRE_HAP_WHITE = {
    "resources/base/media/": ["*.png", "*.json", "*.jpg", "*.jpeg", "*.gif", "*.svg"]
}

OHRE_HAP_BLACK = {
    "*": ["*.proto",
          "*.o", "*.h", "*.cpp", "*.c", "*.cc",
          "*.java", "*.go", "*.cs"],
    ".git": ["*"],
    ".svn": ["*"]
}

OHRE_APP_WHITE = {
    ".": ["pack.info", "*.hap"]
}
