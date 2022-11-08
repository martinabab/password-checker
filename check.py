'''
A program that checks if your password has ever been pwned.
Using haveibeenpwned.com's API
'''

import hashlib
import requests
import sys


def request_data(query_char):
    # query_char  ->  5 char long string; sha1

    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code} - check the API and try again')
    return response


def read_data(api_data):
    # returns a generator object creating lists [hash password tail, its count]
    hashes = (line.split(':') for line in api_data.text.splitlines())
    return hashes


def check_if_pwned(password):
    # convert password to HASH sha1
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5, tail = sha1_password[:5], sha1_password[5:]

    # check if your password occurs in the data
    for h, count in read_data(request_data(first5)):  # ...in read requested data by first 5 characters from a char
        if h == tail:
            return count
    return 0


def main(args):
    for password in args:
        count = check_if_pwned(password)
        if count:
            print(f'Password {password} has been hacked {count} times')
        else:
            print(f'Password {password} has never been hacked')


if __name__ == '__main__':
    main(sys.argv[1:])
