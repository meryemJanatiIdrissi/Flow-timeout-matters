import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from utils.data_utils import  dataset



class LocalUpdate(object):
    def __init__(self, config, x_train=None, y_train=None):
        self.config = config
        self.loss_func = nn.MSELoss() # nn.CrossEntropyLoss()   # reduction='mean'
        self.ldr_train = DataLoader(list(zip(x_train,y_train)), batch_size=self.config.batch_size, shuffle=True,drop_last=True)
        self.criterion = nn.CrossEntropyLoss()  #nn.NLLLoss().to(self.config.device)
    
    def train_net(self, net, timeout):
             
        net.train()
        optimizer = torch.optim.Adam(net.parameters(), lr=self.config.lr, weight_decay=self.config.weight_decay)
        epoch_loss = []
        
        for iter in range(self.config.local_ep):
            batch_loss = []
            for batch_idx, (x, y) in enumerate(self.ldr_train):
                x, y = x.to(self.config.device).float(), y.type(torch.LongTensor).to(self.config.device)

                net.zero_grad()
                log_probs = net(x)
                loss = self.criterion(log_probs, y)
                loss.backward()
                optimizer.step()
                batch_loss.append(loss.item())
            epoch_loss.append(sum(batch_loss)/len(batch_loss))
            
            if self.config.verbose:
                print('Timeout : {} \tLocal Epoch : {} \tLoss: {:.6f}'.format(timeout, iter, epoch_loss[-1]))
        return net, sum(epoch_loss) / len(epoch_loss)