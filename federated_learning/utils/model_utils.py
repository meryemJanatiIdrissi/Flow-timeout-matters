import torch


def save_model(epoch, model, filepath):
    state = {
        'epoch': epoch,
        'state_dict': model.state_dict(),
       
    }
    torch.save(state, filepath)

def load_model(filepath):

    state = torch.load(filepath)

    return state
