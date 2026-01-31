clc; clear; close all;

tsharkPath = '/Applications/Wireshark.app/Contents/MacOS/tshark';
interface  = 'bridge100';  % <-- replacing with the name of host-only
packetBatch = 20;         % packets per batch read from tshark
pauseBetweenBatches = 0.8; % time in seconds

% Loading the trained model
try
    mdl = loadLearnerForCoder('IDS_Model');
catch
    % fallback: try loading mat file incase the above didn't work
    if exist('IDS_Model.mat','file')
        tmp = load('IDS_Model.mat');
        fn = fieldnames(tmp);
        mdl = tmp.(fn{1});
    else
        error('IDS_Model not found in path. Train/save and try again.');
    end
end
fprintf('Loaded IDS model.\n');

% Loading normalization (mu,sigma)
if exist('IDS_Normalization.mat','file')
    S = load('IDS_Normalization.mat','mu','sigma');
    mu = S.mu; sigma = S.sigma;
else
    warning('IDS_Normalization.mat not found. Using mu=zeros, sigma=ones (no scaling).');
    mu = zeros(1,41); sigma = ones(1,41);
end
sigma(sigma==0) = 1;

% Setting up Live plot 
nShow = 200;
predLog = nan(1,nShow);
figure('Name','Live IDS — Host Capture','NumberTitle','off');
ax1 = subplot(2,1,1);
hSt = stairs(ax1, 1:nShow, predLog, 'LineWidth', 1.5);
ylim(ax1,[-0.2 1.2]); ylabel(ax1,'Prediction (0 normal / 1 attack)');
grid on;
ax2 = subplot(2,1,2);
hTxt = text(0.02,0.5,'Waiting for packets...','FontSize',12,'Units','normalized');
axis off;

fprintf('Starting live detection on interface %s. Press Ctrl+C to stop.\n', interface);

% Main loop for capturing the packets
while ishandle(hSt)
    % Running tshark for a small batch
    cmd = sprintf('%s -i %s -c %d -T fields -e frame.number -e ip.src -e ip.dst -e frame.len -e ip.proto -e udp.srcport -e udp.dstport -e sip.Method -E header=n -E separator=,', ...
        tsharkPath, interface, packetBatch);
    [status, raw] = system(cmd);
    if status ~= 0
        warning('tshark returned non-zero status (%d). Check permissions and interface.', status);
        pause(1);
        continue;
    end
    raw = strtrim(raw);
    if isempty(raw)
        pause(pauseBetweenBatches);
        continue;
    end

    rows = strsplit(raw, '\n');
    for r = 1:numel(rows)
        row = strtrim(rows{r});
        if isempty(row), continue; end
        cols = strsplit(row, ',');
        % parsing robustly
        pktNum = NaN; src=''; dst=''; pktLen = NaN; protoNum = NaN; sport=NaN; dport=NaN; sipMethod='';
        if numel(cols)>=1, pktNum = str2double(cols{1}); end
        if numel(cols)>=2, src = cols{2}; end
        if numel(cols)>=3, dst = cols{3}; end
        if numel(cols)>=4, pktLen = str2double(cols{4}); end
        if numel(cols)>=5, protoNum = str2double(cols{5}); end
        if numel(cols)>=6, sport = str2double(cols{6}); end
        if numel(cols)>=7, dport = str2double(cols{7}); end
        if numel(cols)>=8, sipMethod = cols{8}; end

        % Building feature vector (1x41) - to adapt the model for better mapping
        feat = zeros(1,41);
        feat(1) = nanToZero(pktLen);
        feat(2) = nanToZero(protoNum);
        feat(3) = nanToZero(sport);
        feat(4) = nanToZero(dport);
        feat(5) = ~isempty(sipMethod);  % SIP flag
        % (Windowed features separately to improve detection)

        % Normalizing the features
        feat_n = (feat - mu) ./ sigma;

        % Predicting the packtype of packet into Normal or Intrusion
        try
            pred = predict(mdl, feat_n);
            pred = double(pred);
            if ~(pred==0 || pred==1), pred = double(pred>0.5); end
        catch ME
            warning('Predict error: %s', ME.message);
            pred = 0;
        end

        % Updating the display on console
        tstr = datestr(now,'HH:MM:SS.FFF');
        if pred == 1
            fprintf('[%s] 🚨 INTRUSION pkt#%s src=%s dst=%s len=%d proto=%s SIP=%s\n', tstr, num2str(pktNum), src, dst, pktLen, num2str(protoNum), sipMethod);
        else
            fprintf('[%s] ✅ normal   pkt#%s src=%s dst=%s len=%d proto=%s SIP=%s\n', tstr, num2str(pktNum), src, dst, pktLen, num2str(protoNum), sipMethod);
        end

        % Updating the plot
        predLog = [predLog(2:end), pred];
        set(hSt,'YData',predLog,'XData',1:numel(predLog));
        set(hTxt,'String',sprintf('Last: %s -> %s | pred=%d', src, dst, pred));
        drawnow limitrate;
    end

    pause(pauseBetweenBatches);
end

% In case the feature vector is NaN or Zero
function x = nanToZero(v)
    if isempty(v) || isnan(v), x = 0; else x = v; end
end
