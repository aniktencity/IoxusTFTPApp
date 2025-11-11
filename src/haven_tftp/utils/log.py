class LogBus:
    def __init__(self): self.items=[]
    def write(self, msg): self.items.append(msg)
    def drain(self): out=self.items; self.items=[]; return out
