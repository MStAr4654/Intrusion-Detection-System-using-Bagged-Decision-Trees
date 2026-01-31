%% IDS_Model_Comparison.m
% Compare SVM, Decision Tree, KNN, and Ensemble (Bagged Trees) models

clc; clear; close all;

%% === Phase 1: Data Loading and Preprocessing ===

% Define column headers
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

% Load datasets
trainData = readtable('Dataset_NSL-KDD/KDDTrain+.txt', 'ReadVariableNames', false);
trainData.Properties.VariableNames = headers;

testData = readtable('Dataset_NSL-KDD/KDDTest+.txt', 'ReadVariableNames', false);
testData.Properties.VariableNames = headers;

% Encode categorical features
trainData.protocol_type = grp2idx(categorical(trainData.protocol_type));
trainData.service = grp2idx(categorical(trainData.service));
trainData.flag = grp2idx(categorical(trainData.flag));

testData.protocol_type = grp2idx(categorical(testData.protocol_type));
testData.service = grp2idx(categorical(testData.service));
testData.flag = grp2idx(categorical(testData.flag));

% Binary label: normal = 0, attack = 1
trainData.label = double(~strcmp(trainData.label, 'normal'));
testData.label = double(~strcmp(testData.label, 'normal'));

% Extract features and labels
X_train = trainData{:, 1:41};
Y_train = trainData.label;
X_test  = testData{:, 1:41};
Y_test  = testData.label;

% Normalize data
[X_train, mu, sigma] = zscore(X_train);
X_test = (X_test - mu) ./ sigma;

%% === Phase 2: Subset for faster comparison ===
subsetSize = 20000;
X_train_sub = X_train(1:subsetSize, :);
Y_train_sub = Y_train(1:subsetSize);

fprintf('\nTraining and testing IDS models...\n');

%% Helper function to compute metrics
computeMetrics = @(Y_true, Y_pred) struct( ...
    'Accuracy', sum(Y_pred==Y_true)/numel(Y_true), ...
    'ConfMat', confusionmat(Y_true, Y_pred), ...
    'Precision', sum((Y_true==1)&(Y_pred==1)) / max(sum(Y_pred==1),1), ...
    'Recall', sum((Y_true==1)&(Y_pred==1)) / max(sum(Y_true==1),1), ...
    'F1', 2*sum((Y_true==1)&(Y_pred==1)) / max(sum(Y_pred==1)+sum(Y_true==1),1) );

%% === Model 1: Support Vector Machine (SVM) ===
fprintf('\n=== Training SVM Model ===\n');
SVMModel = fitcsvm(X_train_sub, Y_train_sub, ...
    'KernelFunction', 'linear', 'BoxConstraint', 1, 'Standardize', true);
Y_pred_svm = predict(SVMModel, X_test);
metrics.SVM = computeMetrics(Y_test, Y_pred_svm);

%% === Model 2: Decision Tree ===
fprintf('\n=== Training Decision Tree ===\n');
TreeModel = fitctree(X_train_sub, Y_train_sub, 'MaxNumSplits', 100);
Y_pred_tree = predict(TreeModel, X_test);
metrics.Tree = computeMetrics(Y_test, Y_pred_tree);

%% === Model 3: K-Nearest Neighbors (KNN) ===
fprintf('\n=== Training KNN Model ===\n');
KNNModel = fitcknn(X_train_sub, Y_train_sub, 'NumNeighbors', 5, 'Standardize', true);
Y_pred_knn = predict(KNNModel, X_test);
metrics.KNN = computeMetrics(Y_test, Y_pred_knn);

%% === Model 4: Ensemble (Bagged Decision Trees) ===
fprintf('\n=== Training Ensemble (Bagged Trees) ===\n');
EnsembleModel = fitcensemble(X_train_sub, Y_train_sub, 'Method', 'Bag', ...
    'NumLearningCycles', 100);
Y_pred_ens = predict(EnsembleModel, X_test);
metrics.Ensemble = computeMetrics(Y_test, Y_pred_ens);

%% === Phase 3: Display results ===
fprintf('\n\n========= MODEL PERFORMANCE COMPARISON =========\n');

modelNames = fieldnames(metrics);
for i = 1:numel(modelNames)
    m = metrics.(modelNames{i});
    fprintf('\nModel: %s\n', modelNames{i});
    fprintf('Accuracy  : %.2f%%\n', m.Accuracy*100);
    fprintf('Precision : %.2f%%\n', m.Precision*100);
    fprintf('Recall    : %.2f%%\n', m.Recall*100);
    fprintf('F1-Score  : %.2f%%\n', m.F1*100);
    disp('Confusion Matrix:');
    disp(m.ConfMat);
end

%% === Optional: Plot comparison ===
Acc = cellfun(@(x) metrics.(x).Accuracy*100, modelNames);
figure;
bar(Acc);
set(gca, 'XTickLabel', modelNames, 'FontWeight', 'bold');
ylabel('Accuracy (%)');
title('IDS Model Performance Comparison');
grid on;

%% === Confusion Matrix Visualization for All Models ===
figure('Name','Confusion Matrices','NumberTitle','off');
modelNames = fieldnames(metrics);

for i = 1:numel(modelNames)
    subplot(2,2,i);
    cm = confusionchart(metrics.(modelNames{i}).ConfMat);
    cm.Title = sprintf('%s Confusion Matrix', modelNames{i});
    cm.RowSummary = 'row-normalized';
    cm.ColumnSummary = 'column-normalized';
end


fprintf('\n=================================================\n');
