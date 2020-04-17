import requests  # to work with the API
import hashlib  # to use the sha1 hash
import sys  # to pass args in the command line


def request_api_data(query_char):  # check connexion with the API
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):  # splites the hash from the count returned by the API
    # and check if our password was licked and return count
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):  # hash the given passwords in args, give the hashed password and the reponce list
    # from API to get password leaks count fonction
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):  # the main function receives the passwords passed in args in command line
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
