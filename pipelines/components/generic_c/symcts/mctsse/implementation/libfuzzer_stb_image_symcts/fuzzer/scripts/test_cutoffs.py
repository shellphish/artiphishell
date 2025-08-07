#  Import modules
import math
import random
import sys
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
import numpy as np
from sklearn import tree
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV

# Figures inline and set visualization style
# %matplotlib inline
# sns.set()

# Import data
# df_train = pd.read_csv('data/train.csv')
# df_test = pd.read_csv('data/test.csv')

def policy_recent_or_never(row):
    return row['inputs_since_last_successful'] < 0.1 or row['num_successful_mutations'] == 0

def policy_cautious(row):
    if row['times_seen_feasible'] < 100: # if we haven't seen it at least 100 times satisfiable, definitely try it
        return True
    if row['num_inputs_produced'] < 100: # if we haven't produced at least 100 inputs for it, definitely try it
        return True
    if row['num_successful_mutations'] == 0: # if we haven't seen any successful mutations, definitely try it
        return True
    if row['inputs_since_last_successful'] < row['num_inputs_produced'] * 0.1: # if we have seen a successful mutation recently, definitely try it
        return True
    return False

def policy_test(row):
    # if row['num_inputs_produced'] < 100:
    #     return True
    if row['num_inputs_produced'] > row['num_successful_mutations'] * row['times_seen_feasible']:
        return False

    # if row['inputs_since_last_successful'] < row['num_inputs_produced'] * 0.5:
    #     return True
    # if row['times_seen_feasible'] < row['times_seen']:
    #     return True
    return True


data = pd.read_csv(sys.argv[1], sep=', ', names=['times_seen', 'times_seen_symbolic', 'times_seen_feasible', 'num_inputs_produced', 'num_successful_mutations', 'inputs_since_last_successful', 'result'])
# data = pd.read_json(sys.argv[1])

data = pd.DataFrame(data)
print(data.describe())

# divide num_inputs_produced, num_successful_mutations, num_inputs_since_last_successful_mutation by len(data)
# data['num_successful_mutations'] = data['num_successful_mutations'] / len(data)
# data['inputs_since_last_successful'] = data['inputs_since_last_successful'] / len(data)

# Get one hot encoding of columns B
one_hot = pd.get_dummies(data['result'])
# Drop column B as it is now encoded
data = data.drop('result',axis = 1)
# Join the encoded df
data = data.join(one_hot)
print(data.describe())

data['percent'] = data['num_successful_mutations'] / (data['num_inputs_produced'])

X, y = data.iloc[:,:-4],data.iloc[:,-4]
X_test, y_test = X, y

policy = globals()['policy_' + sys.argv[2]]
preds = [policy(row) for index, row in X.iterrows()]

dataset_percentage = sum(y) / len(y)

correct = 0
randomly_correct = 0
correct_zero = 0
total = len(y_test)
false_positives = 0
false_negatives = 0
true_positives = 0
true_negatives = 0
assert len(y_test) == len(preds)
for i, result in enumerate(zip(y_test, preds)):
    rand_guess = 1 if random.random() < dataset_percentage else 0
    # print(result)
    if result[0] == 0:
        correct_zero += 1
    if rand_guess == result[0]:
        randomly_correct += 1
    if result[0] == 1 and result[1] == 0:
        # print("### False negative: \n{}\n\n".format(X_test.iloc[i]))
        false_negatives += 1
    if result[0] == 0 and result[1] == 1:
        # print("### False positive: \n{}\n\n".format(X_test.iloc[i]))
        false_positives += 1
    if result[0] == 1 and result[1] == 1:
        true_positives += 1
    if result[0] == 0 and result[1] == 0:
        true_negatives += 1
    if (result[0] == 1 and result[1] > 0.5) or (result[0] == 0 and result[1] <= 0.5):
        correct += 1
print("Accuracy of always guessing 0: {}/{} = {}".format(correct_zero, len(y_test), correct_zero/len(y_test)))
print("Accuracy of random guessing: {}/{} = {}".format(randomly_correct, total, randomly_correct/total))
print("Accuracy: {}/{} = {}".format(correct, total, correct/total))
print("Number of 1s in the prediction: {}, number of ones in the real test set: {}".format(sum(preds), sum(y_test)))
print("False positives: {}, false negatives: {}".format(false_positives, false_negatives))
print("True positives: {}, true negatives: {}".format(true_positives, true_negatives))


# plot histogram of
# rmse = np.sqrt(mean_squared_error(y_test, preds))
# print("RMSE: %f" % (rmse))~