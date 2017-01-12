

class Where(object):
    def __init__(self, pred): self.pred = pred
    def __eq__(self, other): return self.pred(other)
    def find(self,iterator):
        for v in iterator:
            if self == v:
                return v
        return None