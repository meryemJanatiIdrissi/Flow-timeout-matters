import torch

class MLPConfig():
    def __init__(self,**kwargs):

        #-------------Model params -----------#
        self.latent_size = 100
        self.batch_size=128
        self.hidden_size = 256
        self.lr=1e-3
        self.weight_decay=1e-5
        self.momentum=0.9
        self.mu=0
        
        

        #-------------Training params -----------#
        self.model="MLP"
        self.local_ep=5 #10
        self.epochs=3 #10
        self.gpu = 0 # -1 --> CPU else GPU
        self.device = torch.device('cuda:{}'.format(self.gpu) if torch.cuda.is_available() and self.gpu != -1 else 'cpu')
        self.seed = 123
        self.num_users = 32
        self.all_clients = False
        self.frac = 0.5
        self.iid = True
        self.data_type = "tabular"
        self.verbose = True


        #-------------Dataset params -----------#
        self.dataset = "ustc" # Options: Mnist, nsl-kdd, unsw
        self.abn_cls_idx = 0
        
    def __repr__(self):
        return 