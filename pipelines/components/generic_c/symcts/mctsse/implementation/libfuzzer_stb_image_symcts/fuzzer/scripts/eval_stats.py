#  Import modules
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

data = pd.read_csv(sys.argv[1], sep=', ', names=['times_seen', 'times_seen_symbolic', 'times_seen_feasible', 'num_inputs_produced', 'num_successful_mutations', 'num_inputs_since_last_successful_mutation', 'result'])

data = pd.DataFrame(data)
print(data.describe())

# divide num_inputs_produced, num_successful_mutations, num_inputs_since_last_successful_mutation by len(data)
data['num_inputs_produced'] = data['num_inputs_produced'] / len(data)
data['num_successful_mutations'] = data['num_successful_mutations'] / len(data)
data['num_inputs_since_last_successful_mutation'] = data['num_inputs_since_last_successful_mutation'] / len(data)

# Get one hot encoding of columns B
one_hot = pd.get_dummies(data['result'])
# Drop column B as it is now encoded
data = data.drop('result',axis = 1)
# Join the encoded df
data = data.join(one_hot)
print(data.describe())

data['percent'] = data['num_successful_mutations'] / (data['num_inputs_produced'])

X, y = data.iloc[:,:-4],data.iloc[:,-4]
# data.plot(x='num_inputs_since_last_successful_mutation', y = 'num_inputs_produced', c='Corpus', colormap='gist_rainbow', kind='scatter')
# plt.show()

# # data_dmatrix = xgb.DMatrix(data=X,label=y)

from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=123)

from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score


dataset_percentage = sum(y_train) / len(y_train)

model = DecisionTreeClassifier(max_depth=3, class_weight="balanced", criterion="gini")
# model.fit(X_train, y_train, sample_weight=[1-dataset_percentage if x == 1 else dataset_percentage for x in y_train])
model.fit(X_train, y_train)
print(accuracy_score(y_test, model.predict(X_test)))

# # model = xgb.XGBRegressor(objective ='reg:squarederror', colsample_bytree = 0.3, learning_rate = 0.1,
# #                 max_depth = 5, alpha = 10, n_estimators = 10)

# # model = LogisticRegression(solver='lbfgs', max_iter=1000)


# model = tree.DecisionTreeClassifier(max_depth=10, class_weight={0: 1-dataset_percentage, 1: dataset_percentage})
# # model.fit(X, y)

# model.fit(X_train, y_train)

preds = model.predict(X_test)

correct = 0
randomly_correct = 0
correct_zero = 0
total = len(y_test)
false_positives = 0
false_negatives = 0
true_positives = 0
true_negatives = 0
assert len(y_test) == len(preds)
for result in zip(y_test, preds):
    rand_guess = 1 if random.random() < dataset_percentage else 0
    # print(result)
    if result[0] == 0:
        correct_zero += 1
    if rand_guess == result[0]:
        randomly_correct += 1
    if result[0] == 1 and result[1] == 0:
        false_negatives += 1
    if result[0] == 0 and result[1] == 1:
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

import dtreeviz
viz = dtreeviz.dtreeviz(model, X_train, y_train, target_name='Corpus', feature_names=X_train.columns, class_names=['0', '1'])
viz.save("tree.svg")
viz.view()

# plot histogram of
# rmse = np.sqrt(mean_squared_error(y_test, preds))
# print("RMSE: %f" % (rmse))~