#!/usr/bin/env python
# coding: utf-8

# <h1>Loading in the Datasets for Bluetooth Benign and DoS Test and Train Sets</h1>

# In[1]:


import pandas as pd


# In[2]:


benignTrain = pd.read_csv('Bluetooth_Benign_train.csv')
benignTest = pd.read_csv('Bluetooth_Benign_test.csv')
DoSTrain = pd.read_csv('Bluetooth_DoS_train.csv')
DoSTest = pd.read_csv('Bluetooth_DoS_test.csv')


# In[3]:


benignTrain.head()


# In[4]:


benignTrain


# In[5]:


benignTest.head()


# In[6]:


DoSTrain.head()


# In[7]:


DoSTrain


# In[8]:


DoSTest.head()


# <h1>Cleaning the Data</h1>

# <h3>Adding a new column, "Attack", which will have the value 1 to represent an attack or 0 to represent benign network traffic. This will be the value to be predicted.</h3>

# In[9]:


benignTrain['Attack'] = 0


# In[10]:


benignTrain.head()


# In[11]:


benignTest['Attack'] = 0


# In[12]:


benignTest.head()


# In[13]:


DoSTrain['Attack'] = 1


# In[14]:


DoSTrain.head()


# In[15]:


DoSTest['Attack'] = 1


# In[16]:


DoSTest.head()


# <h3>Merging the Benign and DoS files</h3>

# In[17]:


dataTrainDoS = pd.concat([benignTrain, DoSTrain], ignore_index=True)


# In[18]:


dataTrainDoS


# In[19]:


dataTestDoS = pd.concat([benignTest, DoSTest], ignore_index=True)


# In[20]:


dataTestDoS


# <h1>Data Preprocessing</h1>

# <h3>Converting the non-numerical data to numerical values</h3>

# In[21]:


from sklearn.preprocessing import LabelEncoder


# In[22]:


enc = LabelEncoder()


# In[23]:


dataTrainDoS['Source'] = enc.fit_transform(dataTrainDoS['Source'])


# In[24]:


dataTrainDoS['Destination'] = enc.fit_transform(dataTrainDoS['Destination'])


# In[25]:


dataTrainDoS['Protocol'] = enc.fit_transform(dataTrainDoS['Protocol'])


# In[26]:


dataTrainDoS['Info'] = enc.fit_transform(dataTrainDoS['Info'])


# In[27]:


dataTestDoS['Source'] = enc.fit_transform(dataTestDoS['Source'])


# In[28]:


dataTestDoS['Destination'] = enc.fit_transform(dataTestDoS['Destination'])


# In[29]:


dataTestDoS['Protocol'] = enc.fit_transform(dataTestDoS['Protocol'])


# In[30]:


dataTestDoS['Info'] = enc.fit_transform(dataTestDoS['Info'])


# In[31]:


dataTrainDoS


# In[32]:


dataTestDoS


# <h1>Loading the Dataframes into CSV Files</h1>

# In[33]:


dataTrainDoS.to_csv('dataTrainDoS.csv', index=False)


# In[34]:


dataTestDoS.to_csv('dataTestDoS.csv', index=False)


# <h1>Implementing Decision Tree</h1>

# In[35]:


X_train_DoS = dataTrainDoS.iloc[:, 0:7]
y_train_DoS = dataTrainDoS.iloc[:, 7]


# In[36]:


X_test_DoS = dataTestDoS.iloc[:, 0:7]
y_test_DoS = dataTestDoS.iloc[:, 7]


# In[37]:


print(X_train_DoS.shape)
print(y_train_DoS.shape)
print(X_test_DoS.shape)
print(y_test_DoS.shape)


# In[38]:


from sklearn.tree import DecisionTreeClassifier


# In[39]:


decisionTree = DecisionTreeClassifier()


# In[40]:


decisionTree.fit(X_train_DoS, y_train_DoS)


# In[41]:


y_pred_DoS = decisionTree.predict(X_test_DoS)


# In[42]:


from sklearn.metrics import confusion_matrix


# In[43]:


print(confusion_matrix(y_test_DoS, y_pred_DoS))


# In[44]:


import seaborn as sn
import matplotlib.pyplot as plt
cm = confusion_matrix(y_test_DoS, y_pred_DoS)
df_cm = pd.DataFrame(cm)
plt.figure(figsize=(10, 7))
sn.set(font_scale=0.8)
cmap = sn.cm.rocket_r
sn.heatmap(df_cm, annot=True, cmap=cmap)
plt.show()


# In[45]:


from sklearn.metrics import classification_report


# In[46]:


print(classification_report(y_test_DoS, y_pred_DoS, zero_division=0))


# In[47]:


featImportances = pd.DataFrame(decisionTree.feature_importances_, index = X_test_DoS.columns)
featImportances


# <h1>Loading in the Datasets for Wifi and MQTT Benign and ARP Spoofing Test and Train Sets</h1>

# In[48]:


benignTrain = pd.read_csv('Benign_train.pcap.csv')
benignTest = pd.read_csv('Benign_test.pcap.csv')
ARPSpoofTrain = pd.read_csv('ARP_Spoofing_train.pcap.csv')
ARPSpoofTest = pd.read_csv('ARP_Spoofing_test.pcap.csv')


# In[49]:


benignTrain.head()


# In[50]:


benignTest.head()


# In[51]:


ARPSpoofTrain.head()


# In[52]:


ARPSpoofTest.head()


# <h1>Data Preprocessing</h1>

# <h3>Adding a new column, "Attack", which will have the value 1 to represent an attack or 0 to represent benign network traffic. This will be the value to be predicted.</h3>

# In[53]:


benignTrain['Attack'] = 0
benignTest['Attack'] = 0
ARPSpoofTrain['Attack'] = 1
ARPSpoofTest['Attack'] = 1


# In[54]:


benignTrain.head()


# In[55]:


benignTest.head()


# In[56]:


ARPSpoofTrain.head()


# In[57]:


ARPSpoofTest.head()


# <h3>Merging the Benign and ARPSpoof files</h3>

# In[58]:


dataTrainARP = pd.concat([benignTrain, ARPSpoofTrain], ignore_index=True)


# In[59]:


dataTrainARP


# In[60]:


dataTestARP = pd.concat([benignTest, ARPSpoofTest], ignore_index=True)


# In[61]:


dataTestARP


# <h1>Loading the Dataframes into CSV Files</h1>

# In[62]:


dataTrainARP.to_csv('dataTrainARP.csv', index=False)


# In[63]:


dataTestARP.to_csv('dataTestARP.csv', index=False)


# <h1>Implementing Decision Tree</h1>

# In[64]:


X_train_ARP = dataTrainARP.iloc[:, 0:45]
y_train_ARP = dataTrainARP.iloc[:, 45]


# In[65]:


X_test_ARP = dataTestARP.iloc[:, 0:45]
y_test_ARP = dataTestARP.iloc[:, 45]


# In[66]:


print(X_train_ARP.shape)
print(y_train_ARP.shape)
print(X_test_ARP.shape)
print(y_test_ARP.shape)


# In[67]:


decisionTree.fit(X_train_ARP, y_train_ARP)


# In[68]:


y_pred_ARP = decisionTree.predict(X_test_ARP)


# In[69]:


print(confusion_matrix(y_test_ARP, y_pred_ARP))


# In[70]:


cm = confusion_matrix(y_test_ARP, y_pred_ARP)
df_cm = pd.DataFrame(cm)
plt.figure(figsize=(10, 7))
sn.set(font_scale=0.8)
cmap = sn.cm.rocket_r
sn.heatmap(df_cm, annot=True, cmap=cmap)
plt.show()


# In[71]:


print(classification_report(y_test_ARP, y_pred_ARP, zero_division=0))


# In[72]:


featImportances2 = pd.DataFrame(decisionTree.feature_importances_, index = X_test_ARP.columns)
featImportances2


# <h1>Implementing Diverse Machine Learning Models</h1>

# <h2>Implementing Random Forest for DoS Detection</h2>

# In[ ]:


from sklearn.ensemble import RandomForestClassifier
rfc = RandomForestClassifier(criterion='gini', max_depth=8, min_samples_split=10, random_state=5)


# In[ ]:


rfc.fit(X_train_DoS, y_train_DoS)


# In[ ]:


y_pred_rfc_DoS = rfc.predict(X_test_DoS)


# In[ ]:


print(classification_report(y_test_DoS, y_pred_rfc_DoS, zero_division=0))


# <h2>Implementing Random Forest for ARP Spoofing Detection</h2>

# In[ ]:


rfc.fit(X_train_ARP, y_train_ARP)


# In[ ]:


y_pred_rfc_ARP = rfc.predict(X_test_ARP)


# In[ ]:


print(classification_report(y_test_ARP, y_pred_rfc_ARP, zero_division=0))


# <h2>Trying with greater max depth and lower minimum samples needed to split</h2>

# <h3>ARP</h3>

# In[ ]:


rfc2 = RandomForestClassifier(criterion='gini', max_depth=10, min_samples_split=5, random_state=5)


# In[ ]:


rfc2.fit(X_train_ARP, y_train_ARP)


# In[ ]:


y_pred_rfc2_ARP = rfc2.predict(X_test_ARP)


# In[ ]:


print(classification_report(y_test_ARP, y_pred_rfc2_ARP, zero_division=0))


# In[ ]:


rfc3 = RandomForestClassifier(criterion='gini', max_depth=15, min_samples_split=3, random_state=5)


# In[ ]:


rfc3.fit(X_train_ARP, y_train_ARP)


# In[ ]:


y_pred_rfc3_ARP = rfc3.predict(X_test_ARP)


# In[ ]:


print(classification_report(y_test_ARP, y_pred_rfc3_ARP, zero_division=0))


# <h4>rfc3 was overfit, rfc2 was more accurate</h4>

# <h3>DoS with rfc2</h3>

# In[ ]:


rfc2.fit(X_train_DoS, y_train_DoS)


# In[ ]:


y_pred_rfc2_DoS = rfc2.predict(X_test_DoS)


# In[ ]:


print(classification_report(y_test_DoS, y_pred_rfc2_DoS, zero_division=0))


# <h2>Implementing Gradient Boosting for DoS Detection</h2>

# In[ ]:


from sklearn.ensemble import GradientBoostingClassifier


# In[ ]:


gbc = GradientBoostingClassifier(n_estimators=300, learning_rate=0.05, random_state=100, max_features=5 )


# In[ ]:


gbc.fit(X_train_DoS, y_train_DoS)


# In[ ]:


y_pred_gbc_DoS = gbc.predict(X_test_DoS)


# In[ ]:


print(classification_report(y_test_DoS, y_pred_gbc_DoS, zero_division=0))


# <h2>Implementing Gradient Boosting for ARP Spoofing Detection</h2>

# In[ ]:


gbc.fit(X_train_ARP, y_train_ARP)


# In[ ]:


y_pred_gbc_ARP = gbc.predict(X_test_ARP)


# In[ ]:


print(classification_report(y_test_ARP, y_pred_gbc_ARP, zero_division=0))


# <h2>Implementing XGBoost for DoS Detection</h2>

# In[ ]:


conda install conda=24.5.0


# In[ ]:


conda install -c conda-forge xgboost


# In[ ]:


import xgboost as xgb


# In[ ]:


xgb_train_DoS = xgb.DMatrix(X_train_DoS, y_train_DoS, enable_categorical=True)
xgb_test_DoS = xgb.DMatrix(X_test_DoS, y_test_DoS, enable_categorical=True)


# In[ ]:


n=50
params = {'objective': 'binary:logistic', 'max_depth': 3, 'learning_rate': 0.1,} 
xgb_DoS = xgb.train(params=params, dtrain=xgb_train_DoS, num_boost_round=n)


# In[ ]:


from sklearn.metrics import accuracy_score
preds_DoS = xgb_DoS.predict(xgb_test_DoS)
preds_DoS = preds_DoS.astype(int)
accuracy_DoS = accuracy_score(y_test_DoS, preds_DoS)
print('Accuracy of the model is:', accuracy_DoS*100)


# In[ ]:


print(classification_report(y_test_DoS, preds_DoS, zero_division=0))


# <h2>Implementing XGBoost for ARP Spoofing Detection</h2>

# In[ ]:


xgb_train_ARP = xgb.DMatrix(X_train_ARP, y_train_ARP, enable_categorical=True)
xgb_test_ARP = xgb.DMatrix(X_test_ARP, y_test_ARP, enable_categorical=True)


# In[ ]:


n=50
params = {'objective': 'binary:logistic', 'max_depth': 3, 'learning_rate': 0.1,} 
xgb_ARP = xgb.train(params=params, dtrain=xgb_train_ARP, num_boost_round=n)


# In[ ]:


preds_ARP = xgb_ARP.predict(xgb_test_ARP)
preds_ARP = preds_ARP.astype(int)
accuracy_ARP = accuracy_score(y_test_ARP, preds_ARP)
print('Accuracy of the model is:', accuracy_ARP*100)


# In[ ]:


print(classification_report(y_test_ARP, preds_ARP, zero_division=0))


# <h1>Neural Networks</h1>

# <h2>Implementing Recurrent Neural Networks for DoS Detection</h2>

# In[ ]:


import tensorflow as tf


# In[ ]:


from tensorflow.keras.layers import SimpleRNN, Dense


# In[ ]:


model = tf.keras.Sequential([
    SimpleRNN(50, return_sequences=True, input_shape=(None, 1)),
    SimpleRNN(50),
    Dense(1)
])


# In[ ]:


model.compile(optimizer='adam', loss='mean_squared_error')


# In[ ]:


model.fit(X_train_DoS, y_train_DoS, epochs=10)


# In[ ]:


model.evaluate(X_test_DoS, y_test_DoS)


# In[ ]:


from sklearn.metrics import accuracy_score
preds_neural_DoS = model.predict(X_test_DoS)
preds_neural_DoS = preds_neural_DoS.astype(int)
accuracy_neural_DoS = accuracy_score(y_test_DoS, preds_neural_DoS)
print('Accuracy of the model is:', accuracy_neural_DoS*100)


# In[ ]:


from sklearn.metrics import classification_report
print(classification_report(y_test_DoS, preds_neural_DoS, zero_division=0))


# <h2>Implementing Recurrent Neural Networks for ARP Spoofing Detection</h2>

# In[ ]:


model2 = tf.keras.Sequential([
    SimpleRNN(50, return_sequences=True, input_shape=(None, 1)),
    SimpleRNN(50),
    Dense(1)
])


# In[ ]:


model2.compile(optimizer='adam', loss='mean_squared_error')


# In[ ]:


model2.fit(X_train_ARP, y_train_ARP, epochs=10)


# In[ ]:


model2.evaluate(X_test_ARP, y_test_ARP)


# In[ ]:


preds_neural_ARP = model2.predict(X_test_ARP)
preds_neural_ARP = preds_neural_ARP.astype(int)
accuracy_neural_ARP = accuracy_score(y_test_ARP, preds_neural_ARP)
print('Accuracy of the model is:', accuracy_neural_ARP*100)


# In[ ]:


print(classification_report(y_test_ARP, preds_neural_ARP, zero_division=0))


# <h1>Isolation Forest</h1>

# <h2>DoS Detection</h2>

# In[ ]:


from sklearn.ensemble import IsolationForest
import seaborn as sns


# In[ ]:


df_DoS_Iso = pd.read_csv('dataTrainDoS.csv')


# In[ ]:


df_DoS_Iso = df_DoS_Iso.drop(['Attack'], axis=1)


# In[ ]:


df_DoS_Iso.head()


# In[ ]:


df_DoS_Iso.info()


# In[ ]:


anomaly_inputs_DoS = ['Time', 'Info']


# In[ ]:


model_IF_DoS = IsolationForest(contamination=0.1, random_state=42)


# In[ ]:


model_IF_DoS.fit(df_DoS_Iso[anomaly_inputs_DoS])


# In[ ]:


df_DoS_Iso['Anomaly_scores'] = model_IF_DoS.decision_function(df_DoS_Iso[anomaly_inputs_DoS])


# In[ ]:


df_DoS_Iso['Anomaly'] = model_IF_DoS.predict(df_DoS_Iso[anomaly_inputs_DoS])


# In[ ]:


df_DoS_Iso.loc[:, ['Time', 'Info', 'Anomaly_scores', 'Anomaly'] ]


# In[ ]:


def outlier_plot(data, outlier_method_name, x_var, y_var, xaxis_limits=[0,1], yaxis_limits=[0,1]):
    
    print(f'Outlier Method: {outlier_method_name}')
    
    method = f'{outlier_method_name}_anomaly'
    
    print(f"Number of anomalous values {len(data[data['Anomaly']==-1])}")
    print(f"Number of non-anomalous values {len(data[data['Anomaly']==1])}")
    print(f'Total Number of Values: {len(data)}')
    
    g = sns.FacetGrid(data, col='Anomaly', height=4, hue='Anomaly', hue_order=[1,-1])
    g.map(sns.scatterplot, x_var, y_var)
    g.fig.suptitle(f'Outlier Method: {outlier_method_name}', y=1.10, fontweight='bold')
    g.set(xlim=xaxis_limits, ylim=yaxis_limits)
    axes = g.axes.flatten()
    axes[0].set_title(f"Outliers\n{len(data[data['Anomaly']==-1])} points")
    axes[1].set_title(f"Inliers\n{len(data[data['Anomaly']==1])} points")
    return g


# In[ ]:


outlier_plot(df_DoS_Iso, "Isolation Forest", "Time", "Info", [0,2.0e+06], [0,1000])


# In[ ]:


from sklearn.metrics import silhouette_score


# In[ ]:


X_IF_DoS = df_DoS_Iso[anomaly_inputs_DoS]


# In[ ]:


labels_IF_DoS = model_IF_DoS.predict(X_IF_DoS)


# In[ ]:


sample_size = 10000
score_DoS = silhouette_score(X_IF_DoS, labels_IF_DoS, metric='euclidean', sample_size=sample_size)
print(f'Silhouette Score: {score_DoS}')


# In[ ]:


# silhouette_avg_IF_DoS = silhouette_score(df_DoS_Iso[anomaly_inputs_DoS], labels_IF_DoS)
# print(f'Silhouette Score: {silhouette_avg_IF_DoS}')


# In[ ]:


model_IF_DoS2 = IsolationForest(contamination=0.3, random_state=42)


# In[ ]:


model_IF_DoS2.fit(df_DoS_Iso[anomaly_inputs_DoS])


# In[ ]:


df_DoS_Iso['Anomaly_scores'] = model_IF_DoS2.decision_function(df_DoS_Iso[anomaly_inputs_DoS])
df_DoS_Iso['Anomaly'] = model_IF_DoS2.predict(df_DoS_Iso[anomaly_inputs_DoS])


# In[ ]:


df_DoS_Iso.loc[:, ['Time', 'Info', 'Anomaly_scores', 'Anomaly'] ]


# In[ ]:


outlier_plot(df_DoS_Iso, "Isolation Forest", "Time", "Info", [0,2.0e+06], [0,1000])


# In[ ]:


X_IF_DoS2 = df_DoS_Iso[anomaly_inputs_DoS]


# In[ ]:


labels_IF_DoS2 = model_IF_DoS2.predict(X_IF_DoS2)


# In[ ]:


sample_size = 10000
score_DoS2 = silhouette_score(X_IF_DoS2, labels_IF_DoS2, metric='euclidean', sample_size=sample_size)
print(f'Silhouette Score: {score_DoS2}')


# <h2>ARP Spoofing Detection</h2>

# In[ ]:


df_ARP_Iso = pd.read_csv('dataTrainARP.csv')


# In[ ]:


df_ARP_Iso = df_ARP_Iso.drop(['Attack'], axis=1)


# In[ ]:


df_ARP_Iso.head()


# In[ ]:


df_ARP_Iso.info()


# In[ ]:


anomaly_inputs_ARP = ['Header_Length', 'IAT']


# In[ ]:


model_IF_ARP = IsolationForest(contamination=0.1, random_state=42)


# In[ ]:


model_IF_ARP.fit(df_ARP_Iso[anomaly_inputs_ARP])


# In[ ]:


df_ARP_Iso['Anomaly_scores'] = model_IF_ARP.decision_function(df_ARP_Iso[anomaly_inputs_ARP])
df_ARP_Iso['Anomaly'] = model_IF_ARP.predict(df_ARP_Iso[anomaly_inputs_ARP])


# In[ ]:


df_ARP_Iso.loc[:, ['Header_Length', 'IAT', 'Anomaly_scores', 'Anomaly'] ]


# In[ ]:


outlier_plot(df_ARP_Iso, "Isolation Forest", "Header_Length", "IAT", [0,10.0e+06], [0,2.0e+08])


# In[ ]:


X_IF_ARP = df_ARP_Iso[anomaly_inputs_ARP]


# In[ ]:


labels_IF_ARP = model_IF_ARP.predict(X_IF_ARP)


# In[ ]:


sample_size = 10000
score_ARP = silhouette_score(X_IF_ARP, labels_IF_ARP, metric='euclidean', sample_size=sample_size)
print(f'Silhouette Score: {score_ARP}')


# In[ ]:


model_IF_ARP2 = IsolationForest(contamination=0.3, random_state=42)


# In[ ]:


model_IF_ARP2.fit(df_ARP_Iso[anomaly_inputs_ARP])


# In[ ]:


df_ARP_Iso['Anomaly_scores'] = model_IF_ARP2.decision_function(df_ARP_Iso[anomaly_inputs_ARP])
df_ARP_Iso['Anomaly'] = model_IF_ARP2.predict(df_ARP_Iso[anomaly_inputs_ARP])


# In[ ]:


df_ARP_Iso.loc[:, ['Header_Length', 'IAT', 'Anomaly_scores', 'Anomaly'] ]


# In[ ]:


outlier_plot(df_ARP_Iso, "Isolation Forest", "Header_Length", "IAT", [0,10.0e+06], [0,2.0e+08])


# In[ ]:


X_IF_ARP2 = df_ARP_Iso[anomaly_inputs_ARP]


# In[ ]:


labels_IF_ARP2 = model_IF_ARP2.predict(X_IF_ARP2)


# In[ ]:


sample_size = 10000
score_ARP2 = silhouette_score(X_IF_ARP2, labels_IF_ARP2, metric='euclidean', sample_size=sample_size)
print(f'Silhouette Score: {score_ARP2}')


# <h1>Feature Selection</h1>

# <h3>DoS</h3>

# In[73]:


from sklearn.feature_selection import SelectKBest


# In[74]:


from sklearn.feature_selection import chi2


# In[75]:


import numpy as np


# In[76]:


# Feature extraction
chi_best = SelectKBest(score_func=chi2, k=4)
k_best = chi_best.fit(X_train_DoS, y_train_DoS)

# Summarize scores
np.set_printoptions(precision=3)
print(k_best.scores_)

k_features = k_best.transform(X_train_DoS)
# Summarize selected features
print(k_features[0:5,:])


# In[90]:


# 4 best features are No., Time, Length, and Info


# In[78]:


X_train_DoS_Selection = pd.concat([X_train_DoS.iloc[:, :2], X_train_DoS.iloc[:, -2:]], axis=1)


# In[79]:


X_train_DoS_Selection.head()


# In[80]:


X_test_DoS_Selection = pd.concat([X_test_DoS.iloc[:, :2], X_test_DoS.iloc[:, -2:]], axis=1)


# In[81]:


X_test_DoS_Selection.head()


# In[82]:


decisionTreeSelection = DecisionTreeClassifier()


# In[83]:


decisionTreeSelection.fit(X_train_DoS_Selection, y_train_DoS)


# In[84]:


y_pred_DoS_Selection = decisionTreeSelection.predict(X_test_DoS_Selection)


# In[85]:


print(classification_report(y_test_DoS, y_pred_DoS_Selection, zero_division=0))


# In[86]:


# Accuracy decreased from 0.87 to 0.83


# <h3>ARP Spoofing</h3>

# In[88]:


X_train_ARP = X_train_ARP.abs()
y_train_ARP = y_train_ARP.abs()


# In[89]:


# Feature extraction
chi_best_2 = SelectKBest(score_func=chi2, k=4)
k_best_2 = chi_best_2.fit(X_train_ARP, y_train_ARP)

# Summarize scores
np.set_printoptions(precision=3)
print(k_best_2.scores_)

k_features_2 = k_best_2.transform(X_train_ARP)
# Summarize selected features
print(k_features_2[0:5,:])


# In[91]:


# 4 best features are Header_Length, Covariance, Max, and rst_count


# In[95]:


X_train_ARP_Selection = pd.concat([X_train_ARP['Header_Length'], X_train_ARP['Covariance'], X_train_ARP['Max'], X_train_ARP['rst_count']], axis=1)


# In[96]:


X_train_ARP_Selection.head()


# In[101]:


X_test_ARP_Selection = pd.concat([X_test_ARP['Header_Length'], X_test_ARP['Covariance'], X_test_ARP['Max'], X_test_ARP['rst_count']], axis=1)


# In[102]:


X_test_ARP_Selection.head()


# In[97]:


decisionTreeSelection2 = DecisionTreeClassifier()


# In[98]:


decisionTreeSelection2.fit(X_train_ARP_Selection, y_train_ARP)


# In[103]:


y_pred_ARP_Selection = decisionTreeSelection2.predict(X_test_ARP_Selection)


# In[104]:


print(classification_report(y_test_ARP, y_pred_ARP_Selection, zero_division=0))


# In[105]:


# accuracy decreased from 0.95 to 0.90

