#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace {

struct FunctionCoveragePass : public PassInfoMixin<FunctionCoveragePass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
        LLVMContext &Ctx = M.getContext();
        
        // Declare func_cov function
        FunctionType *FuncCovType = FunctionType::get(
            Type::getVoidTy(Ctx),
            {PointerType::get(IntegerType::getInt8Ty(Ctx), 0),
             IntegerType::getInt32Ty(Ctx)},
            false);
        
        FunctionCallee FuncCovFunc = M.getOrInsertFunction("func_cov", FuncCovType);

        // Lambda to check if function name starts with "sancov." or "asan."
        auto isSkippable = [](StringRef Name) {
            return Name.starts_with("sancov.") || Name.starts_with("asan.") || Name.starts_with("_ZNSt3");
        };
        
        for (Function &F : M) {
            // Skip functions that are declarations or have no basic blocks
            if (F.isDeclaration() || F.empty())
                continue;

            // Skip functions that start with "sancov." or "asan."
            if (isSkippable(F.getName()))
                continue;

            errs() << "Processing function: " << F.getName() << "\n";

            // Create IRBuilder
            IRBuilder<> Builder(Ctx);

            // Insert instrumentation at the beginning of the function
            BasicBlock &EntryBB = F.getEntryBlock();
            Builder.SetInsertPoint(&EntryBB, EntryBB.getFirstInsertionPt());

            // Create function name string and get its length
            Value *FuncName = Builder.CreateGlobalStringPtr(F.getName());
            Value *NameLength = ConstantInt::get(IntegerType::getInt32Ty(Ctx), F.getName().size());

            // Insert func_cov call
            Builder.CreateCall(FuncCovFunc, {FuncName, NameLength});
        }

        return PreservedAnalyses::none();
    }
};

} // end anonymous namespace

// Register the pass
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "FunctionCoverage", LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "function-coverage") {
                        MPM.addPass(FunctionCoveragePass());
                        return true;
                    }
                    return false;
                });
        }};
}