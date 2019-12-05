from netzob.all import *

def import_file(filename):
    """
    :param filename: pcap file name
    using netzob to import message
    :return:message(byte type)
    """
    message = PCAPImporter.readFile(filename).values()
    symbol = Symbol(messages=message)
    message = symbol.getValues()
    return message


def is_text_type(message):
    """
    judge whether this whole message is printable
    :param message: message(type: bytes)
    :return: Ture or False
    """
    for i in range(len(message)):
        if message[i] < 32 or message[i] > 127:
            if message[i] == 10 or message[i] == 13:
                continue
            return False
    return True


def is_mixed_type(message,window_wize):
    """
    under the condition that messages are not text type, to judge messages are whther mixed type
    :param message: message
    :param window_wize: judge text size
    :return: Ture or False
    """
    for i in range(len(message)-window_wize+1):
        for j in range(i,i + window_wize):
            if message[j] < 32 or message[j] > 127:
                if message[j] != 13 or message[j] != 10:
                    break
            if j == i+window_wize-1:
                return True
        return False

def MessageClassifier(messages):
    """
    classify messages into text, binary and mixed type
    :param messages: set of message
    :return: text binary mixed type messages(set of message)
    """
    text_type = []
    mixed_type = []
    bin_type = []

    for i in range(len(messages)):
        if is_text_type(messages[i]) == True:
            text_type.append(messages[i])
        elif is_mixed_type(messages[i],5) == True:
            mixed_type.append(messages[i])
        else:
            bin_type.append(messages[i])

    text_tmp_type = []
    for i in range(len(text_type)):
        if len(text_type[i]) <= 500:
            text_tmp_type.append(text_type[i])

    return text_tmp_type, mixed_type, bin_type

if __name__ == '__main__':
    a = import_file('S7_1.pcap')
    b = import_file('http.pcap')
    c = a + b
    text_type, mixed_type, bin_type = MessageClassifier(c)
    print(len(text_type))
    for i in range(len(text_type)):
        print(text_type[i])
        print(len(text_type[i]))
    # print("")
    # print("")
    # for i in range(len(bin_type)):
    #     print(bin_type[i])
    # print("")
    # print("")
    # for i in range(len(mixed_type)):
    #     print(mixed_type[i])