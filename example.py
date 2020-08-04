import sys

from password_checker import pasword_checker

def main(args):
    for password in args:
        count = pwc.check_password_breach(password)
        if count:
            print(f'{password} was found {count} times. a different password would be recommended')
        else:
            print(f'{password} was not found. no problem here!')

    print(pwc.check_breach_by_name().json())


if __name__ == '__main__':
    pwc = pasword_checker()
    main(sys.argv[1:])