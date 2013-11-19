#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    print sys.path[-1]
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "access_tokens_test.settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
