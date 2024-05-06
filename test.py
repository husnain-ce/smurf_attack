import argparse


parser = argparse.ArgumentParser(description='Smurf attack Automation Tool')
parser.add_argument("-spf","--spoof", help="Spoofed static Ip address, eg: -spf 10.10.10.10 ")
parser.add_argument("-dspf","--dspoof", help="Spoofed dynamic Ip address, eg: -dpf RND")
parser.add_argument("-d","--dest", help="Destination Addr, eg: -d ipv4")
parser.add_argument("-n","--number_of_request", default=100 , help="Number of requests, eg: -n 500")


parser.add_argument("-infi","--infinite", default=True, help="Number of requests infinitly , eg: -infi True")


args = parser.parse_args()


print(args.infinite)
print(type(args.infinite))



counter = 1

test = False

# if type(args.number_of_request) == 'infinite':
#     test = True

# if type(int(args.number_of_request)) == int:
#     number_of_request = int(args.number_of_request)
#     test = False

# def t(test):
#     print(number_of_request)
#     while counter <= number_of_request: 
#             print(counter)
#             counter += 1

# # 