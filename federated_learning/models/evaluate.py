# https://github.com/TooTouch/GAN-based-Anomaly-Detection/blob/main/MAD-GANs/evaluate.py

#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @python: 3.6

import torch
from metrics.AUC import AUC
from metrics.FDR import FDR
from metrics.DR import DR
from metrics.F1 import F1_score
from metrics.ACC import ACC
import torch.nn.functional as F
from torch.autograd import Variable
import numpy as np

from torchmetrics import F1Score, Metric
from torchmetrics import Metric, ConfusionMatrix, Accuracy

def compute_F1Score(preds, labels):
    y_pred = torch.from_numpy(preds)
    y_test = torch.tensor(labels)
    f1score_marco = F1Score(num_classes=2, average="macro")
    f1score_marco(y_pred, y_test)
    f1_macro = f1score_marco.compute()
    return f1_macro

def compute_fdr(preds, labels):
    y_pred = torch.from_numpy(preds)
    y_test = torch.tensor(labels)    
    cfx = ConfusionMatrix(num_classes=2)
    cfx(y_pred, y_test)
    cm = cfx.compute()
    TP, FP = cm[0, 0], cm[1, 0]
    fdr = FP / (FP + TP)  
    return fdr


def compute_acc(preds, labels):
    y_pred = torch.from_numpy(preds)
    y_test = torch.tensor(labels) 
    accuracy = Accuracy()
    accuracy(y_pred, y_test)
    acc = accuracy.compute()
    return acc

def compute_dr(preds, labels):
    y_pred = torch.from_numpy(preds)
    y_test = torch.tensor(labels) 
    cfx = ConfusionMatrix(num_classes=2)
    cfx(y_pred, y_test)
    cm = cfx.compute()
    TP, FN = cm[0, 0], cm[0, 1]
    dr = TP / (FN + TP)
    return dr

class evaluateGAN(object):
    def __init__(self, config):
        self.auc = AUC(pos_label=1)
        self.fdr = FDR(num_classes=2)
        self.dr = DR(num_classes=2)
        self.f1 = F1_score(num_classes=1)
        self.acc = ACC()
        
        self.config = config
        
    def compute_auc(self, preds, labels):
        self.auc(preds, labels)
        AUC = self.auc.compute()

        return AUC

    def compute_FDR(self, preds, labels):
        self.fdr(preds, labels)
        FDR = self.fdr.compute()

        return FDR     

    def compute_DR(self, preds, labels):
        self.dr(preds, labels)
        DR = self.dr.compute()

        return DR
    
    def compute_F1(self, preds, labels):
        self.f1(preds, labels)
        f1 = self.f1.compute()
        return f1

    def compute_ACC(self, preds, labels):
        self.acc(preds, labels)
        DR = self.acc.compute()

        return DR
    
def evaluate_gan(config, net, data_x):
    net.eval()    
    data_x = data_x.view(len(data_x), -1).to(config.device)

    # Detection result
    p_value = net(data_x.float())
    preds = torch.squeeze(p_value, 1)
            
    return preds    
    
def evaluate_ae(config, net, loader):
    all_losses = []
    net.eval()
    loss_func = F.mse_loss
    with torch.no_grad():
        for i, x in enumerate(loader):
            x = Variable(x[0])
            x = x.to(config.device).float()
            x_rec = net(x)
            loss = loss_func(x_rec, x)
            all_losses.append(loss.item())
            
    return all_losses

def get_thr(config, net, loader):
    all_train_losses = evaluate_ae(config, net, loader)
    all_train_losses = np.array(all_train_losses)

    threshold = np.mean(all_train_losses) + np.std(all_train_losses)
    return threshold