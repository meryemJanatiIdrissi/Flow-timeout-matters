# https://github.com/Xiaohui9607/f_anogan_pytorch/blob/a2f4f04b29965889ba0f3c8126c2abcf6843456f/dataloader/dataloader.py#L54

import torch
import numpy as np
from torch.utils.data import Dataset
from .model_utils import load_model
import os
import pandas as pd


    
class dataset(Dataset):
    def __init__(self, dataset, idxs):
        self.dataset = dataset
        self.idxs = list(idxs)

    def __len__(self):
        return len(self.idxs)

    def __getitem__(self, item):
        image = self.dataset[self.idxs[item]]
        return image

