%% Phase 1 - Data Loading and Preprocessing
clc; clear all;

% Defining 43 headers including attack_type
headers = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", ...
"land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", ...
"num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", ...
"num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", ...
"is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", ...
"rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", ...
"srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", ...
"dst_host_same_srv_rate", "dst_host_diff_srv_rate", ...
"dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", ...
"dst_host_serror_rate", "dst_host_srv_serror_rate", ...
"dst_host_rerror_rate", "dst_host_srv_rerror_rate", ...
"label", "attack_type"];

% Loading training data
trainData = readtable('Dataset_NSL-KDD/KDDTrain+.txt', 'ReadVariableNames', false);
trainData.Properties.VariableNames = headers;

% Loading test data
testData = readtable('Dataset_NSL-KDD/KDDTest+.txt', 'ReadVariableNames', false);
testData.Properties.VariableNames = headers;

% Encoding categorical features
trainData.protocol_type = grp2idx(categorical(trainData.protocol_type));
trainData.service = grp2idx(categorical(trainData.service));
trainData.flag = grp2idx(categorical(trainData.flag));

testData.protocol_type = grp2idx(categorical(testData.protocol_type));
testData.service = grp2idx(categorical(testData.service));
testData.flag = grp2idx(categorical(testData.flag));

% Binary labelling: normal = 0, attack = 1
trainData.label = double(~strcmp(trainData.label, 'normal'));
testData.label = double(~strcmp(testData.label, 'normal'));

% Extracting features and labels
X_train = trainData{:, 1:41};  % excluding label & attack_type
Y_train = trainData.label;

X_test = testData{:, 1:41};
Y_test = testData.label;

% Normalizing features
[X_train, mu, sigma] = zscore(X_train);
X_test = (X_test - mu) ./ sigma;
save('IDS_Normalization.mat', 'mu', 'sigma');


%% Phase 2 - Model Training and Evaluation 

subsetSize = 20000;
X_train_sub = X_train(1:subsetSize, :);
Y_train_sub = Y_train(1:subsetSize);
Y_train_sub = Y_train_sub(:);  % ensure column

% Computing weights from the subset ONLY
num0 = sum(Y_train_sub == 0);
num1 = sum(Y_train_sub == 1);
weights = zeros(length(Y_train_sub), 1);
weights(Y_train_sub == 0) = 1 / num0;
weights(Y_train_sub == 1) = 1 / num1;
weights = weights / sum(weights);  % optional normalization

% % Training the model
% SVMModel = fitcsvm(X_train_sub, Y_train_sub, ...
%     'KernelFunction', 'linear', ...
%     'BoxConstraint', 1, ...
%     'ClassNames', [0, 1], ...
%     'Standardize', true, ...
%     'Weights', weights);
% 
% % Predict and evaluate
% Y_pred = predict(SVMModel, X_test);
% accuracy = sum(Y_pred == Y_test) / length(Y_test);
% fprintf('\nSVM Accuracy: %.2f%%\n', accuracy * 100);
% 
% confMat = confusionmat(Y_test, Y_pred);
% disp('Confusion Matrix:');
% disp(confMat);
% 
% tp = confMat(2,2); fp = confMat(1,2); fn = confMat(2,1);
% precision = tp / (tp + fp);
% recall = tp / (tp + fn);
% f1 = 2 * precision * recall / (precision + recall);
% 
% fprintf('Precision: %.2f%%\n', precision * 100);
% fprintf('Recall: %.2f%%\n', recall * 100);
% fprintf('F1-Score: %.2f%%\n', f1 * 100);
% 
% % Save model for Simulink
% saveLearnerForCoder(SVMModel, 'IDS_Model');

% Ensemble Model (works better than SVM on this dataset)
EnsembleModel = fitcensemble(X_train_sub, Y_train_sub, ...
    'Method', 'Bag', ...
    'NumLearningCycles', 100);

% Predicting on test data
Y_pred = predict(EnsembleModel, X_test);

% Evaluating performance
accuracy = sum(Y_pred == Y_test) / length(Y_test);
fprintf('\nEnsemble Accuracy: %.2f%%\n', accuracy * 100);

confMat = confusionmat(Y_test, Y_pred);
disp('Confusion Matrix:');
disp(confMat);

tp = confMat(2,2); fp = confMat(1,2); fn = confMat(2,1);
precision = tp / (tp + fp);
recall = tp / (tp + fn);
f1 = 2 * precision * recall / (precision + recall);

fprintf('Precision: %.2f%%\n', precision * 100);
fprintf('Recall: %.2f%%\n', recall * 100);
fprintf('F1-Score: %.2f%%\n', f1 * 100);

% Saving model for Simulink / Live Packet Capture (PCAP)
saveLearnerForCoder(EnsembleModel, 'IDS_Model');

%% Phase 3: Clearing the TimeSeries data

% Ensuring numeric and clean data for Simulink
X_test_clean = double(X_test);  % Force to double
X_test_clean(isnan(X_test_clean)) = 0;
X_test_clean(isinf(X_test_clean)) = 0;

%% Phase 4 Prep: Converting test data to timeseries for Simulink

% Sample time (e.g., 0.1 seconds per row)
Ts = 0.1;

% Time vector based on number of test samples
t = (0:Ts:Ts*(size(X_test_clean,1)-1))';

% Creating timeseries object
X_test_ts = timeseries(X_test_clean, t);

% Saving to base workspace for Simulink
assignin('base', 'X_test_ts', X_test_ts);

%% Confusion Chart
confchart= confusionchart(Y_test, Y_pred);
