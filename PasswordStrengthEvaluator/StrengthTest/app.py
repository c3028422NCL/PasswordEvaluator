import hashlib
import itertools
import random
import time
from zxcvbn import zxcvbn as estimator
import flask
from flask import render_template, request
import math
app = flask.Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def template():
    colour = ['','','','','']
    colours = []
    if request.method == "POST":
        password = request.form.get("password", "")
        BfSolved, BfSuccess , BfGuesses= bruteforce(password)
        CgSolved, CgSuccess, CgGuesses = common_guess(password)
        DSolved, DSuccess , DGuesses= dictionary(password)
        MkSolved, MkSuccess, MkGuesses = mask(password)
        MgSolved, MgSuccess, MgGuesses = mangling(password)
        results = estimator(password, max_length= 20)
        colours.append(ColourPicker(BfSolved,getstrength('bf', BfSuccess, results,BfGuesses)))
        colours.append(ColourPicker(CgSolved,getstrength('cg', CgSuccess,results,CgGuesses)))
        colours.append(ColourPicker(DSolved,getstrength('d',  DSuccess,results,DGuesses)))
        colours.append(ColourPicker(MgSolved,getstrength('mg',  MgSuccess,results,MgGuesses)))
        colours.append(ColourPicker(MkSolved,getstrength('mk', MkSuccess,results,MkGuesses)))
        stats = []
        stats.append(results["crack_times_display"]["offline_slow_hashing_1e4_per_second"])
        stats.append(results["score"])
        if results["feedback"]["suggestions"]:
            stats.append(results["feedback"]["suggestions"][0])
        else:
            stats.append("This is a strong password, no suggestions :)")

        return render_template('Template.html',stats = stats, password = password, colors=colours)

    return render_template('Template.html', colors=colour)


def getstrength(attack, success, results , guesses):
    attack_weights = {
        "bf": {
            "score": 0.3,
            "success": 0.3,
            "crack": 0.25,
            "guesses": 0.15
        },
        "d": {
            "score": 0.20,
            "success": 0.30,
            "crack": 0.20,
            "guesses": 0.30
        },
        "cg": {
            "score": 0.20,
            "success": 0.30,
            "crack": 0.20,
            "guesses": 0.30
        },
        "mg": {
            "score": 0.35,
            "success": 0.30,
            "crack": 0.20,
            "guesses": 0.15
        },
        "mk": {
            "score": 0.25,
            "success": 0.20,
            "crack": 0.20,
            "guesses": 0.35
        }
    }

    score_norm = results["score"] / 4
    success_norm = 1 - (success / 100)
    seconds = results["crack_times_seconds"]["offline_slow_hashing_1e4_per_second"]
    crack_norm = min(math.log10(seconds + 1) / 10, 1)
    guess_norm = math.log10(guesses) / (1 + math.log10(guesses))
    final_score = (
            attack_weights[attack]["score"] * score_norm +
            attack_weights[attack]["success"] * success_norm +
            attack_weights[attack]["crack"] * crack_norm +
            attack_weights[attack]["guesses"] * guess_norm
    )

    strength = int(final_score * 100)
    print(score_norm,guess_norm,crack_norm,success_norm)
    print(strength)
    return strength

def ColourPicker(solved, strength):
    if solved:
        return "red"
    if strength > 0 and strength <= 40:
        return "yellow"
    if strength >=41 and strength <= 55:
        return "orange"
    if strength >= 56 and strength <= 74:
        return "green"
    if strength >= 75:
        return "darkgreen"



def bruteforce(target):
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!£$%&*@?+#'
    maxlength = 20
    maxtime = 10
    guesses = 0
    targethash = hasher(target)
    start = time.perf_counter()
    success = 0

    for x in range(1, maxlength + 1):
        for combination in itertools.product(charset, repeat=x):
            temp = ''.join(combination)
            guesses += 1

            if successcheck(temp, target) > success:
                success = successcheck(temp, target)

            if hasher(temp) == targethash:
                return (False,success, guesses)

            if time.perf_counter() - start > maxtime:
                return (False, success, guesses)

    return (False, success, guesses)

def common_guess(target):
    start = time.perf_counter()
    guesses = 0
    maxtime = 10
    targethash = hasher(target)
    success = 0
    with open("Mergedpwds.txt","r" , encoding= "utf-8", errors= "ignore") as h:
        for line in h:
            line = line.strip()
            guesses += 1

            if successcheck(line, target) > success:
                success = successcheck(line, target)

            if hasher(line) == targethash:
                return (True,success, guesses)

            if time.perf_counter() - start > maxtime:
                return (False,success, guesses)

    return (False,success, guesses)

def dictionary(target):
    start = time.perf_counter()
    guesses = 0
    maxtime = 10
    targethash = hasher(target)
    success = 0
    with open("Dictionary.txt","r" , encoding= "utf-8", errors= "ignore") as f:
        for line in f:
            line = line.strip()
            guesses += 1
            if successcheck(line, target) > success:
                success = successcheck(line, target)

            if hasher(line) == targethash:
                return (True, success, guesses)

            if time.perf_counter() - start > maxtime:
                return (False, success, guesses)

    return (False, success, guesses)

def mangling(target):
    start = time.perf_counter()
    guesses = 0
    maxtime = 10
    targethash = hasher(target)
    success = 0
    rules =[ [],[upperfirst], [uppercase],[upperpattern], [leetspeak], [appendyear],[appendsymbol],
             [appendnumbers],[duplicate], [prependnumbers],[prependsymbol],[upperfirst,leetspeak],[upperfirst, appendyear],
             [upperfirst, appendsymbol],[upperfirst, appendnumbers],[appendnumbers,appendnumbers],[upperfirst,leetspeak],
             [upperfirst, leetspeak, appendsymbol],[upperfirst,leetspeak, appendyear],[upperpattern,leetspeak]]

    with open("Mangling.txt","r" , encoding= "utf-8", errors= "ignore") as f:
        for line in f:
            line = line.strip()

            for i in range(20):
                newline = line
                for rule in rules[i]:
                    newline = rule(newline)

                guesses += 1
                if successcheck(newline, target) > success:
                    success = successcheck(line, target)

                if hasher(newline) == targethash:
                    return (True, success, guesses)

                if time.perf_counter() - start > maxtime:
                    return (False, success, guesses)

    return (False, success, guesses)

def mask(target):
    key = {'?l': 'abcdefghijklmnopqrstuvwxyz', '?n':'0123456789', '?s': '!£$%&*@?+#',
           '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '?lu': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
           '?ln': 'abcdefghijklmnopqrstuvwxyz0123456789', '?lns': 'abcdefghijklmnopqrstuvwxyz0123456789!£$%&*@?+#'}
    templates = {1: '?ln', 2: '?ln?ln',3:'?ln?ln?ln',4:'?ln?ln?ln?ln',5:'?l?l?l?l?l',6:'?l?l?l?l?ln?ln'
        ,7:'?lu?l?l?l?ln?ln?lns',8:'?lu?l?l?l?l?l?l?lns',9:'?lu?lu?lu?lu?lu?lu?lu?s?s',10:'?lu?lu?lu?lu?lu?lu?lu?s?s?s',
                 11:'?lns?lu?lu?lu?lu?lu?lu?lu?lns?s?s',12:'?lns?lu?lu?lu?lu?lu?lu?lu?lu?lns?s?s',    13: '?lns?lu?lu?lu?lu?lu?lu?lu?lu?lu?lns?s?s',
                 14: '?lns?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lns?s?s',15: '?lns?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lns?s?s',
                 16: '?lns?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lns?s?s',17: '?lns?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lns?s?s',
                 18: '?lns?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lns?s?s',19: '?lns?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lns?s?s',
                 20: '?lns?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lu?lns?s?s'}
    maxlength = 20
    maxtime = 10
    guesses = 0
    targethash= hasher(target)
    start = time.perf_counter()
    success = 0

    for x in range(1, maxlength + 1):
        mask = templates[x]
        newmask = translatemask(mask,key)
        for combination in itertools.product(*newmask):
            temp = ''.join(combination)
            guesses += 1

            if successcheck(temp, target) > success:
                success = successcheck(temp, target)

            if hasher(temp) == targethash:
                return (True, success, guesses)

            if time.perf_counter() - start > maxtime:
                return (False, success, guesses)

    return (False, success, guesses)

def hasher(password):
    return hashlib.sha256(password.encode()).hexdigest()

def successcheck(target, original):
    if not original:
        return 0.0  # avoid division by zero

    count = 0

    for i, char in enumerate(original):
        if i < len(target) and char == target[i]:
            count += 1

    return round((count / len(original)) * 100, 2)

def translatemask(mask, key):
    translation = []
    i = 0

    keys = sorted(key.keys(), key=len, reverse=True)

    while i < len(mask):
        matched = False

        for k in keys:
            if mask.startswith(k, i):
                translation.append(key[k])
                i += len(k)
                matched = True
                break

        if not matched:
            raise ValueError(f"Unknown token at position {i}: {mask[i:]}")

    return translation

def upperfirst(word):
    if not word:
        return word
    if not word[0].isupper():
        return word[0].upper() + word[1:]
    return word
def uppercase(word):
    if not word:
        return word
    else:
        return word.upper()
def upperpattern(word):
    if not word:
        return word
    else:
        result = ""
        for i in range(len(word)):
            if i % 2:
                result += word[i]
            else:
                result += word[i].upper()
        return result
def leetspeak(word):
    char_set = {'a': ['4', '@'], 'e': ['3'],'f': ['ph'], 'i': ['1', '!'], 'l': ['!','1'],
                    'o': ['0'], 's': ['$', '5'], 't': ['7'], '0': ['o'], '8':['&']}
    result = ""
    if not word:
        return word
    for i, char in enumerate(word):
        if char in char_set and random.random() < 0.70:
            temp = random.choice(char_set[char])
            result += temp
        else:
            result += char
    return result
def appendsymbol(word):
    symbol_set = ['!','£','$','%','&','*','@','?','+','#']
    if not word:
        return word
    word = word + random.choice(symbol_set)
    return word
def appendnumbers(word):
    number_set = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    if not word:
        return word
    word = word + random.choice(number_set)
    return word
def appendyear(word, start=1950, end=2026):
    if not word:
        return word
    year = random.randint(start, end)
    word = word + str(year)
    return word
def prependnumbers(word):
    number_set = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    if not word:
        return word
    word = random.choice(number_set) + word
    return word
def prependsymbol(word):
    symbol_set = ['!','£','$','%','&','*','@','?','+','#']
    if not word:
        return word
    word = random.choice(symbol_set) + word
    return word
def duplicate(word):
    if not word:
        return word
    word = word + word
    return word



if __name__ == '__main__':
    app.run(debug = True)