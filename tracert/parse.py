# coding=utf-8
from argparse import ArgumentParser


def get_args():
    parser = ArgumentParser()
    parser.add_argument('Host', help='Choose host to trace')
    return parser.parse_args()
