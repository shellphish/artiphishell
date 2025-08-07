# Generated from JavaParser.g4 by ANTLR 4.13.1
from antlr4 import *
if "." in __name__:
    from .JavaParser import JavaParser
else:
    from JavaParser import JavaParser

# This class defines a complete listener for a parse tree produced by JavaParser.
class JavaParserListener(ParseTreeListener):

    # Enter a parse tree produced by JavaParser#compilationUnit.
    def enterCompilationUnit(self, ctx:JavaParser.CompilationUnitContext):
        pass

    # Exit a parse tree produced by JavaParser#compilationUnit.
    def exitCompilationUnit(self, ctx:JavaParser.CompilationUnitContext):
        pass


    # Enter a parse tree produced by JavaParser#packageDeclaration.
    def enterPackageDeclaration(self, ctx:JavaParser.PackageDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#packageDeclaration.
    def exitPackageDeclaration(self, ctx:JavaParser.PackageDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#importDeclaration.
    def enterImportDeclaration(self, ctx:JavaParser.ImportDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#importDeclaration.
    def exitImportDeclaration(self, ctx:JavaParser.ImportDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#typeDeclaration.
    def enterTypeDeclaration(self, ctx:JavaParser.TypeDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#typeDeclaration.
    def exitTypeDeclaration(self, ctx:JavaParser.TypeDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#modifier.
    def enterModifier(self, ctx:JavaParser.ModifierContext):
        pass

    # Exit a parse tree produced by JavaParser#modifier.
    def exitModifier(self, ctx:JavaParser.ModifierContext):
        pass


    # Enter a parse tree produced by JavaParser#classOrInterfaceModifier.
    def enterClassOrInterfaceModifier(self, ctx:JavaParser.ClassOrInterfaceModifierContext):
        pass

    # Exit a parse tree produced by JavaParser#classOrInterfaceModifier.
    def exitClassOrInterfaceModifier(self, ctx:JavaParser.ClassOrInterfaceModifierContext):
        pass


    # Enter a parse tree produced by JavaParser#variableModifier.
    def enterVariableModifier(self, ctx:JavaParser.VariableModifierContext):
        pass

    # Exit a parse tree produced by JavaParser#variableModifier.
    def exitVariableModifier(self, ctx:JavaParser.VariableModifierContext):
        pass


    # Enter a parse tree produced by JavaParser#classDeclaration.
    def enterClassDeclaration(self, ctx:JavaParser.ClassDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#classDeclaration.
    def exitClassDeclaration(self, ctx:JavaParser.ClassDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#typeParameters.
    def enterTypeParameters(self, ctx:JavaParser.TypeParametersContext):
        pass

    # Exit a parse tree produced by JavaParser#typeParameters.
    def exitTypeParameters(self, ctx:JavaParser.TypeParametersContext):
        pass


    # Enter a parse tree produced by JavaParser#typeParameter.
    def enterTypeParameter(self, ctx:JavaParser.TypeParameterContext):
        pass

    # Exit a parse tree produced by JavaParser#typeParameter.
    def exitTypeParameter(self, ctx:JavaParser.TypeParameterContext):
        pass


    # Enter a parse tree produced by JavaParser#typeBound.
    def enterTypeBound(self, ctx:JavaParser.TypeBoundContext):
        pass

    # Exit a parse tree produced by JavaParser#typeBound.
    def exitTypeBound(self, ctx:JavaParser.TypeBoundContext):
        pass


    # Enter a parse tree produced by JavaParser#enumDeclaration.
    def enterEnumDeclaration(self, ctx:JavaParser.EnumDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#enumDeclaration.
    def exitEnumDeclaration(self, ctx:JavaParser.EnumDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#enumConstants.
    def enterEnumConstants(self, ctx:JavaParser.EnumConstantsContext):
        pass

    # Exit a parse tree produced by JavaParser#enumConstants.
    def exitEnumConstants(self, ctx:JavaParser.EnumConstantsContext):
        pass


    # Enter a parse tree produced by JavaParser#enumConstant.
    def enterEnumConstant(self, ctx:JavaParser.EnumConstantContext):
        pass

    # Exit a parse tree produced by JavaParser#enumConstant.
    def exitEnumConstant(self, ctx:JavaParser.EnumConstantContext):
        pass


    # Enter a parse tree produced by JavaParser#enumBodyDeclarations.
    def enterEnumBodyDeclarations(self, ctx:JavaParser.EnumBodyDeclarationsContext):
        pass

    # Exit a parse tree produced by JavaParser#enumBodyDeclarations.
    def exitEnumBodyDeclarations(self, ctx:JavaParser.EnumBodyDeclarationsContext):
        pass


    # Enter a parse tree produced by JavaParser#interfaceDeclaration.
    def enterInterfaceDeclaration(self, ctx:JavaParser.InterfaceDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#interfaceDeclaration.
    def exitInterfaceDeclaration(self, ctx:JavaParser.InterfaceDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#classBody.
    def enterClassBody(self, ctx:JavaParser.ClassBodyContext):
        pass

    # Exit a parse tree produced by JavaParser#classBody.
    def exitClassBody(self, ctx:JavaParser.ClassBodyContext):
        pass


    # Enter a parse tree produced by JavaParser#interfaceBody.
    def enterInterfaceBody(self, ctx:JavaParser.InterfaceBodyContext):
        pass

    # Exit a parse tree produced by JavaParser#interfaceBody.
    def exitInterfaceBody(self, ctx:JavaParser.InterfaceBodyContext):
        pass


    # Enter a parse tree produced by JavaParser#classBodyDeclaration.
    def enterClassBodyDeclaration(self, ctx:JavaParser.ClassBodyDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#classBodyDeclaration.
    def exitClassBodyDeclaration(self, ctx:JavaParser.ClassBodyDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#memberDeclaration.
    def enterMemberDeclaration(self, ctx:JavaParser.MemberDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#memberDeclaration.
    def exitMemberDeclaration(self, ctx:JavaParser.MemberDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#methodDeclaration.
    def enterMethodDeclaration(self, ctx:JavaParser.MethodDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#methodDeclaration.
    def exitMethodDeclaration(self, ctx:JavaParser.MethodDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#methodBody.
    def enterMethodBody(self, ctx:JavaParser.MethodBodyContext):
        pass

    # Exit a parse tree produced by JavaParser#methodBody.
    def exitMethodBody(self, ctx:JavaParser.MethodBodyContext):
        pass


    # Enter a parse tree produced by JavaParser#typeTypeOrVoid.
    def enterTypeTypeOrVoid(self, ctx:JavaParser.TypeTypeOrVoidContext):
        pass

    # Exit a parse tree produced by JavaParser#typeTypeOrVoid.
    def exitTypeTypeOrVoid(self, ctx:JavaParser.TypeTypeOrVoidContext):
        pass


    # Enter a parse tree produced by JavaParser#genericMethodDeclaration.
    def enterGenericMethodDeclaration(self, ctx:JavaParser.GenericMethodDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#genericMethodDeclaration.
    def exitGenericMethodDeclaration(self, ctx:JavaParser.GenericMethodDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#genericConstructorDeclaration.
    def enterGenericConstructorDeclaration(self, ctx:JavaParser.GenericConstructorDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#genericConstructorDeclaration.
    def exitGenericConstructorDeclaration(self, ctx:JavaParser.GenericConstructorDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#constructorDeclaration.
    def enterConstructorDeclaration(self, ctx:JavaParser.ConstructorDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#constructorDeclaration.
    def exitConstructorDeclaration(self, ctx:JavaParser.ConstructorDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#compactConstructorDeclaration.
    def enterCompactConstructorDeclaration(self, ctx:JavaParser.CompactConstructorDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#compactConstructorDeclaration.
    def exitCompactConstructorDeclaration(self, ctx:JavaParser.CompactConstructorDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#fieldDeclaration.
    def enterFieldDeclaration(self, ctx:JavaParser.FieldDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#fieldDeclaration.
    def exitFieldDeclaration(self, ctx:JavaParser.FieldDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#interfaceBodyDeclaration.
    def enterInterfaceBodyDeclaration(self, ctx:JavaParser.InterfaceBodyDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#interfaceBodyDeclaration.
    def exitInterfaceBodyDeclaration(self, ctx:JavaParser.InterfaceBodyDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#interfaceMemberDeclaration.
    def enterInterfaceMemberDeclaration(self, ctx:JavaParser.InterfaceMemberDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#interfaceMemberDeclaration.
    def exitInterfaceMemberDeclaration(self, ctx:JavaParser.InterfaceMemberDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#constDeclaration.
    def enterConstDeclaration(self, ctx:JavaParser.ConstDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#constDeclaration.
    def exitConstDeclaration(self, ctx:JavaParser.ConstDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#constantDeclarator.
    def enterConstantDeclarator(self, ctx:JavaParser.ConstantDeclaratorContext):
        pass

    # Exit a parse tree produced by JavaParser#constantDeclarator.
    def exitConstantDeclarator(self, ctx:JavaParser.ConstantDeclaratorContext):
        pass


    # Enter a parse tree produced by JavaParser#interfaceMethodDeclaration.
    def enterInterfaceMethodDeclaration(self, ctx:JavaParser.InterfaceMethodDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#interfaceMethodDeclaration.
    def exitInterfaceMethodDeclaration(self, ctx:JavaParser.InterfaceMethodDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#interfaceMethodModifier.
    def enterInterfaceMethodModifier(self, ctx:JavaParser.InterfaceMethodModifierContext):
        pass

    # Exit a parse tree produced by JavaParser#interfaceMethodModifier.
    def exitInterfaceMethodModifier(self, ctx:JavaParser.InterfaceMethodModifierContext):
        pass


    # Enter a parse tree produced by JavaParser#genericInterfaceMethodDeclaration.
    def enterGenericInterfaceMethodDeclaration(self, ctx:JavaParser.GenericInterfaceMethodDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#genericInterfaceMethodDeclaration.
    def exitGenericInterfaceMethodDeclaration(self, ctx:JavaParser.GenericInterfaceMethodDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#interfaceCommonBodyDeclaration.
    def enterInterfaceCommonBodyDeclaration(self, ctx:JavaParser.InterfaceCommonBodyDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#interfaceCommonBodyDeclaration.
    def exitInterfaceCommonBodyDeclaration(self, ctx:JavaParser.InterfaceCommonBodyDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#variableDeclarators.
    def enterVariableDeclarators(self, ctx:JavaParser.VariableDeclaratorsContext):
        pass

    # Exit a parse tree produced by JavaParser#variableDeclarators.
    def exitVariableDeclarators(self, ctx:JavaParser.VariableDeclaratorsContext):
        pass


    # Enter a parse tree produced by JavaParser#variableDeclarator.
    def enterVariableDeclarator(self, ctx:JavaParser.VariableDeclaratorContext):
        pass

    # Exit a parse tree produced by JavaParser#variableDeclarator.
    def exitVariableDeclarator(self, ctx:JavaParser.VariableDeclaratorContext):
        pass


    # Enter a parse tree produced by JavaParser#variableDeclaratorId.
    def enterVariableDeclaratorId(self, ctx:JavaParser.VariableDeclaratorIdContext):
        pass

    # Exit a parse tree produced by JavaParser#variableDeclaratorId.
    def exitVariableDeclaratorId(self, ctx:JavaParser.VariableDeclaratorIdContext):
        pass


    # Enter a parse tree produced by JavaParser#variableInitializer.
    def enterVariableInitializer(self, ctx:JavaParser.VariableInitializerContext):
        pass

    # Exit a parse tree produced by JavaParser#variableInitializer.
    def exitVariableInitializer(self, ctx:JavaParser.VariableInitializerContext):
        pass


    # Enter a parse tree produced by JavaParser#arrayInitializer.
    def enterArrayInitializer(self, ctx:JavaParser.ArrayInitializerContext):
        pass

    # Exit a parse tree produced by JavaParser#arrayInitializer.
    def exitArrayInitializer(self, ctx:JavaParser.ArrayInitializerContext):
        pass


    # Enter a parse tree produced by JavaParser#classOrInterfaceType.
    def enterClassOrInterfaceType(self, ctx:JavaParser.ClassOrInterfaceTypeContext):
        pass

    # Exit a parse tree produced by JavaParser#classOrInterfaceType.
    def exitClassOrInterfaceType(self, ctx:JavaParser.ClassOrInterfaceTypeContext):
        pass


    # Enter a parse tree produced by JavaParser#typeArgument.
    def enterTypeArgument(self, ctx:JavaParser.TypeArgumentContext):
        pass

    # Exit a parse tree produced by JavaParser#typeArgument.
    def exitTypeArgument(self, ctx:JavaParser.TypeArgumentContext):
        pass


    # Enter a parse tree produced by JavaParser#qualifiedNameList.
    def enterQualifiedNameList(self, ctx:JavaParser.QualifiedNameListContext):
        pass

    # Exit a parse tree produced by JavaParser#qualifiedNameList.
    def exitQualifiedNameList(self, ctx:JavaParser.QualifiedNameListContext):
        pass


    # Enter a parse tree produced by JavaParser#formalParameters.
    def enterFormalParameters(self, ctx:JavaParser.FormalParametersContext):
        pass

    # Exit a parse tree produced by JavaParser#formalParameters.
    def exitFormalParameters(self, ctx:JavaParser.FormalParametersContext):
        pass


    # Enter a parse tree produced by JavaParser#receiverParameter.
    def enterReceiverParameter(self, ctx:JavaParser.ReceiverParameterContext):
        pass

    # Exit a parse tree produced by JavaParser#receiverParameter.
    def exitReceiverParameter(self, ctx:JavaParser.ReceiverParameterContext):
        pass


    # Enter a parse tree produced by JavaParser#formalParameterList.
    def enterFormalParameterList(self, ctx:JavaParser.FormalParameterListContext):
        pass

    # Exit a parse tree produced by JavaParser#formalParameterList.
    def exitFormalParameterList(self, ctx:JavaParser.FormalParameterListContext):
        pass


    # Enter a parse tree produced by JavaParser#formalParameter.
    def enterFormalParameter(self, ctx:JavaParser.FormalParameterContext):
        pass

    # Exit a parse tree produced by JavaParser#formalParameter.
    def exitFormalParameter(self, ctx:JavaParser.FormalParameterContext):
        pass


    # Enter a parse tree produced by JavaParser#lastFormalParameter.
    def enterLastFormalParameter(self, ctx:JavaParser.LastFormalParameterContext):
        pass

    # Exit a parse tree produced by JavaParser#lastFormalParameter.
    def exitLastFormalParameter(self, ctx:JavaParser.LastFormalParameterContext):
        pass


    # Enter a parse tree produced by JavaParser#lambdaLVTIList.
    def enterLambdaLVTIList(self, ctx:JavaParser.LambdaLVTIListContext):
        pass

    # Exit a parse tree produced by JavaParser#lambdaLVTIList.
    def exitLambdaLVTIList(self, ctx:JavaParser.LambdaLVTIListContext):
        pass


    # Enter a parse tree produced by JavaParser#lambdaLVTIParameter.
    def enterLambdaLVTIParameter(self, ctx:JavaParser.LambdaLVTIParameterContext):
        pass

    # Exit a parse tree produced by JavaParser#lambdaLVTIParameter.
    def exitLambdaLVTIParameter(self, ctx:JavaParser.LambdaLVTIParameterContext):
        pass


    # Enter a parse tree produced by JavaParser#qualifiedName.
    def enterQualifiedName(self, ctx:JavaParser.QualifiedNameContext):
        pass

    # Exit a parse tree produced by JavaParser#qualifiedName.
    def exitQualifiedName(self, ctx:JavaParser.QualifiedNameContext):
        pass


    # Enter a parse tree produced by JavaParser#literal.
    def enterLiteral(self, ctx:JavaParser.LiteralContext):
        pass

    # Exit a parse tree produced by JavaParser#literal.
    def exitLiteral(self, ctx:JavaParser.LiteralContext):
        pass


    # Enter a parse tree produced by JavaParser#integerLiteral.
    def enterIntegerLiteral(self, ctx:JavaParser.IntegerLiteralContext):
        pass

    # Exit a parse tree produced by JavaParser#integerLiteral.
    def exitIntegerLiteral(self, ctx:JavaParser.IntegerLiteralContext):
        pass


    # Enter a parse tree produced by JavaParser#floatLiteral.
    def enterFloatLiteral(self, ctx:JavaParser.FloatLiteralContext):
        pass

    # Exit a parse tree produced by JavaParser#floatLiteral.
    def exitFloatLiteral(self, ctx:JavaParser.FloatLiteralContext):
        pass


    # Enter a parse tree produced by JavaParser#altAnnotationQualifiedName.
    def enterAltAnnotationQualifiedName(self, ctx:JavaParser.AltAnnotationQualifiedNameContext):
        pass

    # Exit a parse tree produced by JavaParser#altAnnotationQualifiedName.
    def exitAltAnnotationQualifiedName(self, ctx:JavaParser.AltAnnotationQualifiedNameContext):
        pass


    # Enter a parse tree produced by JavaParser#annotation.
    def enterAnnotation(self, ctx:JavaParser.AnnotationContext):
        pass

    # Exit a parse tree produced by JavaParser#annotation.
    def exitAnnotation(self, ctx:JavaParser.AnnotationContext):
        pass


    # Enter a parse tree produced by JavaParser#elementValuePairs.
    def enterElementValuePairs(self, ctx:JavaParser.ElementValuePairsContext):
        pass

    # Exit a parse tree produced by JavaParser#elementValuePairs.
    def exitElementValuePairs(self, ctx:JavaParser.ElementValuePairsContext):
        pass


    # Enter a parse tree produced by JavaParser#elementValuePair.
    def enterElementValuePair(self, ctx:JavaParser.ElementValuePairContext):
        pass

    # Exit a parse tree produced by JavaParser#elementValuePair.
    def exitElementValuePair(self, ctx:JavaParser.ElementValuePairContext):
        pass


    # Enter a parse tree produced by JavaParser#elementValue.
    def enterElementValue(self, ctx:JavaParser.ElementValueContext):
        pass

    # Exit a parse tree produced by JavaParser#elementValue.
    def exitElementValue(self, ctx:JavaParser.ElementValueContext):
        pass


    # Enter a parse tree produced by JavaParser#elementValueArrayInitializer.
    def enterElementValueArrayInitializer(self, ctx:JavaParser.ElementValueArrayInitializerContext):
        pass

    # Exit a parse tree produced by JavaParser#elementValueArrayInitializer.
    def exitElementValueArrayInitializer(self, ctx:JavaParser.ElementValueArrayInitializerContext):
        pass


    # Enter a parse tree produced by JavaParser#annotationTypeDeclaration.
    def enterAnnotationTypeDeclaration(self, ctx:JavaParser.AnnotationTypeDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#annotationTypeDeclaration.
    def exitAnnotationTypeDeclaration(self, ctx:JavaParser.AnnotationTypeDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#annotationTypeBody.
    def enterAnnotationTypeBody(self, ctx:JavaParser.AnnotationTypeBodyContext):
        pass

    # Exit a parse tree produced by JavaParser#annotationTypeBody.
    def exitAnnotationTypeBody(self, ctx:JavaParser.AnnotationTypeBodyContext):
        pass


    # Enter a parse tree produced by JavaParser#annotationTypeElementDeclaration.
    def enterAnnotationTypeElementDeclaration(self, ctx:JavaParser.AnnotationTypeElementDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#annotationTypeElementDeclaration.
    def exitAnnotationTypeElementDeclaration(self, ctx:JavaParser.AnnotationTypeElementDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#annotationTypeElementRest.
    def enterAnnotationTypeElementRest(self, ctx:JavaParser.AnnotationTypeElementRestContext):
        pass

    # Exit a parse tree produced by JavaParser#annotationTypeElementRest.
    def exitAnnotationTypeElementRest(self, ctx:JavaParser.AnnotationTypeElementRestContext):
        pass


    # Enter a parse tree produced by JavaParser#annotationMethodOrConstantRest.
    def enterAnnotationMethodOrConstantRest(self, ctx:JavaParser.AnnotationMethodOrConstantRestContext):
        pass

    # Exit a parse tree produced by JavaParser#annotationMethodOrConstantRest.
    def exitAnnotationMethodOrConstantRest(self, ctx:JavaParser.AnnotationMethodOrConstantRestContext):
        pass


    # Enter a parse tree produced by JavaParser#annotationMethodRest.
    def enterAnnotationMethodRest(self, ctx:JavaParser.AnnotationMethodRestContext):
        pass

    # Exit a parse tree produced by JavaParser#annotationMethodRest.
    def exitAnnotationMethodRest(self, ctx:JavaParser.AnnotationMethodRestContext):
        pass


    # Enter a parse tree produced by JavaParser#annotationConstantRest.
    def enterAnnotationConstantRest(self, ctx:JavaParser.AnnotationConstantRestContext):
        pass

    # Exit a parse tree produced by JavaParser#annotationConstantRest.
    def exitAnnotationConstantRest(self, ctx:JavaParser.AnnotationConstantRestContext):
        pass


    # Enter a parse tree produced by JavaParser#defaultValue.
    def enterDefaultValue(self, ctx:JavaParser.DefaultValueContext):
        pass

    # Exit a parse tree produced by JavaParser#defaultValue.
    def exitDefaultValue(self, ctx:JavaParser.DefaultValueContext):
        pass


    # Enter a parse tree produced by JavaParser#moduleDeclaration.
    def enterModuleDeclaration(self, ctx:JavaParser.ModuleDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#moduleDeclaration.
    def exitModuleDeclaration(self, ctx:JavaParser.ModuleDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#moduleBody.
    def enterModuleBody(self, ctx:JavaParser.ModuleBodyContext):
        pass

    # Exit a parse tree produced by JavaParser#moduleBody.
    def exitModuleBody(self, ctx:JavaParser.ModuleBodyContext):
        pass


    # Enter a parse tree produced by JavaParser#moduleDirective.
    def enterModuleDirective(self, ctx:JavaParser.ModuleDirectiveContext):
        pass

    # Exit a parse tree produced by JavaParser#moduleDirective.
    def exitModuleDirective(self, ctx:JavaParser.ModuleDirectiveContext):
        pass


    # Enter a parse tree produced by JavaParser#requiresModifier.
    def enterRequiresModifier(self, ctx:JavaParser.RequiresModifierContext):
        pass

    # Exit a parse tree produced by JavaParser#requiresModifier.
    def exitRequiresModifier(self, ctx:JavaParser.RequiresModifierContext):
        pass


    # Enter a parse tree produced by JavaParser#recordDeclaration.
    def enterRecordDeclaration(self, ctx:JavaParser.RecordDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#recordDeclaration.
    def exitRecordDeclaration(self, ctx:JavaParser.RecordDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#recordHeader.
    def enterRecordHeader(self, ctx:JavaParser.RecordHeaderContext):
        pass

    # Exit a parse tree produced by JavaParser#recordHeader.
    def exitRecordHeader(self, ctx:JavaParser.RecordHeaderContext):
        pass


    # Enter a parse tree produced by JavaParser#recordComponentList.
    def enterRecordComponentList(self, ctx:JavaParser.RecordComponentListContext):
        pass

    # Exit a parse tree produced by JavaParser#recordComponentList.
    def exitRecordComponentList(self, ctx:JavaParser.RecordComponentListContext):
        pass


    # Enter a parse tree produced by JavaParser#recordComponent.
    def enterRecordComponent(self, ctx:JavaParser.RecordComponentContext):
        pass

    # Exit a parse tree produced by JavaParser#recordComponent.
    def exitRecordComponent(self, ctx:JavaParser.RecordComponentContext):
        pass


    # Enter a parse tree produced by JavaParser#recordBody.
    def enterRecordBody(self, ctx:JavaParser.RecordBodyContext):
        pass

    # Exit a parse tree produced by JavaParser#recordBody.
    def exitRecordBody(self, ctx:JavaParser.RecordBodyContext):
        pass


    # Enter a parse tree produced by JavaParser#block.
    def enterBlock(self, ctx:JavaParser.BlockContext):
        pass

    # Exit a parse tree produced by JavaParser#block.
    def exitBlock(self, ctx:JavaParser.BlockContext):
        pass


    # Enter a parse tree produced by JavaParser#blockStatement.
    def enterBlockStatement(self, ctx:JavaParser.BlockStatementContext):
        pass

    # Exit a parse tree produced by JavaParser#blockStatement.
    def exitBlockStatement(self, ctx:JavaParser.BlockStatementContext):
        pass


    # Enter a parse tree produced by JavaParser#localVariableDeclaration.
    def enterLocalVariableDeclaration(self, ctx:JavaParser.LocalVariableDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#localVariableDeclaration.
    def exitLocalVariableDeclaration(self, ctx:JavaParser.LocalVariableDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#identifier.
    def enterIdentifier(self, ctx:JavaParser.IdentifierContext):
        pass

    # Exit a parse tree produced by JavaParser#identifier.
    def exitIdentifier(self, ctx:JavaParser.IdentifierContext):
        pass


    # Enter a parse tree produced by JavaParser#typeIdentifier.
    def enterTypeIdentifier(self, ctx:JavaParser.TypeIdentifierContext):
        pass

    # Exit a parse tree produced by JavaParser#typeIdentifier.
    def exitTypeIdentifier(self, ctx:JavaParser.TypeIdentifierContext):
        pass


    # Enter a parse tree produced by JavaParser#localTypeDeclaration.
    def enterLocalTypeDeclaration(self, ctx:JavaParser.LocalTypeDeclarationContext):
        pass

    # Exit a parse tree produced by JavaParser#localTypeDeclaration.
    def exitLocalTypeDeclaration(self, ctx:JavaParser.LocalTypeDeclarationContext):
        pass


    # Enter a parse tree produced by JavaParser#statement.
    def enterStatement(self, ctx:JavaParser.StatementContext):
        pass

    # Exit a parse tree produced by JavaParser#statement.
    def exitStatement(self, ctx:JavaParser.StatementContext):
        pass


    # Enter a parse tree produced by JavaParser#catchClause.
    def enterCatchClause(self, ctx:JavaParser.CatchClauseContext):
        pass

    # Exit a parse tree produced by JavaParser#catchClause.
    def exitCatchClause(self, ctx:JavaParser.CatchClauseContext):
        pass


    # Enter a parse tree produced by JavaParser#catchType.
    def enterCatchType(self, ctx:JavaParser.CatchTypeContext):
        pass

    # Exit a parse tree produced by JavaParser#catchType.
    def exitCatchType(self, ctx:JavaParser.CatchTypeContext):
        pass


    # Enter a parse tree produced by JavaParser#finallyBlock.
    def enterFinallyBlock(self, ctx:JavaParser.FinallyBlockContext):
        pass

    # Exit a parse tree produced by JavaParser#finallyBlock.
    def exitFinallyBlock(self, ctx:JavaParser.FinallyBlockContext):
        pass


    # Enter a parse tree produced by JavaParser#resourceSpecification.
    def enterResourceSpecification(self, ctx:JavaParser.ResourceSpecificationContext):
        pass

    # Exit a parse tree produced by JavaParser#resourceSpecification.
    def exitResourceSpecification(self, ctx:JavaParser.ResourceSpecificationContext):
        pass


    # Enter a parse tree produced by JavaParser#resources.
    def enterResources(self, ctx:JavaParser.ResourcesContext):
        pass

    # Exit a parse tree produced by JavaParser#resources.
    def exitResources(self, ctx:JavaParser.ResourcesContext):
        pass


    # Enter a parse tree produced by JavaParser#resource.
    def enterResource(self, ctx:JavaParser.ResourceContext):
        pass

    # Exit a parse tree produced by JavaParser#resource.
    def exitResource(self, ctx:JavaParser.ResourceContext):
        pass


    # Enter a parse tree produced by JavaParser#switchBlockStatementGroup.
    def enterSwitchBlockStatementGroup(self, ctx:JavaParser.SwitchBlockStatementGroupContext):
        pass

    # Exit a parse tree produced by JavaParser#switchBlockStatementGroup.
    def exitSwitchBlockStatementGroup(self, ctx:JavaParser.SwitchBlockStatementGroupContext):
        pass


    # Enter a parse tree produced by JavaParser#switchLabel.
    def enterSwitchLabel(self, ctx:JavaParser.SwitchLabelContext):
        pass

    # Exit a parse tree produced by JavaParser#switchLabel.
    def exitSwitchLabel(self, ctx:JavaParser.SwitchLabelContext):
        pass


    # Enter a parse tree produced by JavaParser#forControl.
    def enterForControl(self, ctx:JavaParser.ForControlContext):
        pass

    # Exit a parse tree produced by JavaParser#forControl.
    def exitForControl(self, ctx:JavaParser.ForControlContext):
        pass


    # Enter a parse tree produced by JavaParser#forInit.
    def enterForInit(self, ctx:JavaParser.ForInitContext):
        pass

    # Exit a parse tree produced by JavaParser#forInit.
    def exitForInit(self, ctx:JavaParser.ForInitContext):
        pass


    # Enter a parse tree produced by JavaParser#enhancedForControl.
    def enterEnhancedForControl(self, ctx:JavaParser.EnhancedForControlContext):
        pass

    # Exit a parse tree produced by JavaParser#enhancedForControl.
    def exitEnhancedForControl(self, ctx:JavaParser.EnhancedForControlContext):
        pass


    # Enter a parse tree produced by JavaParser#parExpression.
    def enterParExpression(self, ctx:JavaParser.ParExpressionContext):
        pass

    # Exit a parse tree produced by JavaParser#parExpression.
    def exitParExpression(self, ctx:JavaParser.ParExpressionContext):
        pass


    # Enter a parse tree produced by JavaParser#expressionList.
    def enterExpressionList(self, ctx:JavaParser.ExpressionListContext):
        pass

    # Exit a parse tree produced by JavaParser#expressionList.
    def exitExpressionList(self, ctx:JavaParser.ExpressionListContext):
        pass


    # Enter a parse tree produced by JavaParser#methodCall.
    def enterMethodCall(self, ctx:JavaParser.MethodCallContext):
        pass

    # Exit a parse tree produced by JavaParser#methodCall.
    def exitMethodCall(self, ctx:JavaParser.MethodCallContext):
        pass


    # Enter a parse tree produced by JavaParser#expression.
    def enterExpression(self, ctx:JavaParser.ExpressionContext):
        pass

    # Exit a parse tree produced by JavaParser#expression.
    def exitExpression(self, ctx:JavaParser.ExpressionContext):
        pass


    # Enter a parse tree produced by JavaParser#pattern.
    def enterPattern(self, ctx:JavaParser.PatternContext):
        pass

    # Exit a parse tree produced by JavaParser#pattern.
    def exitPattern(self, ctx:JavaParser.PatternContext):
        pass


    # Enter a parse tree produced by JavaParser#lambdaExpression.
    def enterLambdaExpression(self, ctx:JavaParser.LambdaExpressionContext):
        pass

    # Exit a parse tree produced by JavaParser#lambdaExpression.
    def exitLambdaExpression(self, ctx:JavaParser.LambdaExpressionContext):
        pass


    # Enter a parse tree produced by JavaParser#lambdaParameters.
    def enterLambdaParameters(self, ctx:JavaParser.LambdaParametersContext):
        pass

    # Exit a parse tree produced by JavaParser#lambdaParameters.
    def exitLambdaParameters(self, ctx:JavaParser.LambdaParametersContext):
        pass


    # Enter a parse tree produced by JavaParser#lambdaBody.
    def enterLambdaBody(self, ctx:JavaParser.LambdaBodyContext):
        pass

    # Exit a parse tree produced by JavaParser#lambdaBody.
    def exitLambdaBody(self, ctx:JavaParser.LambdaBodyContext):
        pass


    # Enter a parse tree produced by JavaParser#primary.
    def enterPrimary(self, ctx:JavaParser.PrimaryContext):
        pass

    # Exit a parse tree produced by JavaParser#primary.
    def exitPrimary(self, ctx:JavaParser.PrimaryContext):
        pass


    # Enter a parse tree produced by JavaParser#switchExpression.
    def enterSwitchExpression(self, ctx:JavaParser.SwitchExpressionContext):
        pass

    # Exit a parse tree produced by JavaParser#switchExpression.
    def exitSwitchExpression(self, ctx:JavaParser.SwitchExpressionContext):
        pass


    # Enter a parse tree produced by JavaParser#switchLabeledRule.
    def enterSwitchLabeledRule(self, ctx:JavaParser.SwitchLabeledRuleContext):
        pass

    # Exit a parse tree produced by JavaParser#switchLabeledRule.
    def exitSwitchLabeledRule(self, ctx:JavaParser.SwitchLabeledRuleContext):
        pass


    # Enter a parse tree produced by JavaParser#guardedPattern.
    def enterGuardedPattern(self, ctx:JavaParser.GuardedPatternContext):
        pass

    # Exit a parse tree produced by JavaParser#guardedPattern.
    def exitGuardedPattern(self, ctx:JavaParser.GuardedPatternContext):
        pass


    # Enter a parse tree produced by JavaParser#switchRuleOutcome.
    def enterSwitchRuleOutcome(self, ctx:JavaParser.SwitchRuleOutcomeContext):
        pass

    # Exit a parse tree produced by JavaParser#switchRuleOutcome.
    def exitSwitchRuleOutcome(self, ctx:JavaParser.SwitchRuleOutcomeContext):
        pass


    # Enter a parse tree produced by JavaParser#classType.
    def enterClassType(self, ctx:JavaParser.ClassTypeContext):
        pass

    # Exit a parse tree produced by JavaParser#classType.
    def exitClassType(self, ctx:JavaParser.ClassTypeContext):
        pass


    # Enter a parse tree produced by JavaParser#creator.
    def enterCreator(self, ctx:JavaParser.CreatorContext):
        pass

    # Exit a parse tree produced by JavaParser#creator.
    def exitCreator(self, ctx:JavaParser.CreatorContext):
        pass


    # Enter a parse tree produced by JavaParser#createdName.
    def enterCreatedName(self, ctx:JavaParser.CreatedNameContext):
        pass

    # Exit a parse tree produced by JavaParser#createdName.
    def exitCreatedName(self, ctx:JavaParser.CreatedNameContext):
        pass


    # Enter a parse tree produced by JavaParser#innerCreator.
    def enterInnerCreator(self, ctx:JavaParser.InnerCreatorContext):
        pass

    # Exit a parse tree produced by JavaParser#innerCreator.
    def exitInnerCreator(self, ctx:JavaParser.InnerCreatorContext):
        pass


    # Enter a parse tree produced by JavaParser#arrayCreatorRest.
    def enterArrayCreatorRest(self, ctx:JavaParser.ArrayCreatorRestContext):
        pass

    # Exit a parse tree produced by JavaParser#arrayCreatorRest.
    def exitArrayCreatorRest(self, ctx:JavaParser.ArrayCreatorRestContext):
        pass


    # Enter a parse tree produced by JavaParser#classCreatorRest.
    def enterClassCreatorRest(self, ctx:JavaParser.ClassCreatorRestContext):
        pass

    # Exit a parse tree produced by JavaParser#classCreatorRest.
    def exitClassCreatorRest(self, ctx:JavaParser.ClassCreatorRestContext):
        pass


    # Enter a parse tree produced by JavaParser#explicitGenericInvocation.
    def enterExplicitGenericInvocation(self, ctx:JavaParser.ExplicitGenericInvocationContext):
        pass

    # Exit a parse tree produced by JavaParser#explicitGenericInvocation.
    def exitExplicitGenericInvocation(self, ctx:JavaParser.ExplicitGenericInvocationContext):
        pass


    # Enter a parse tree produced by JavaParser#typeArgumentsOrDiamond.
    def enterTypeArgumentsOrDiamond(self, ctx:JavaParser.TypeArgumentsOrDiamondContext):
        pass

    # Exit a parse tree produced by JavaParser#typeArgumentsOrDiamond.
    def exitTypeArgumentsOrDiamond(self, ctx:JavaParser.TypeArgumentsOrDiamondContext):
        pass


    # Enter a parse tree produced by JavaParser#nonWildcardTypeArgumentsOrDiamond.
    def enterNonWildcardTypeArgumentsOrDiamond(self, ctx:JavaParser.NonWildcardTypeArgumentsOrDiamondContext):
        pass

    # Exit a parse tree produced by JavaParser#nonWildcardTypeArgumentsOrDiamond.
    def exitNonWildcardTypeArgumentsOrDiamond(self, ctx:JavaParser.NonWildcardTypeArgumentsOrDiamondContext):
        pass


    # Enter a parse tree produced by JavaParser#nonWildcardTypeArguments.
    def enterNonWildcardTypeArguments(self, ctx:JavaParser.NonWildcardTypeArgumentsContext):
        pass

    # Exit a parse tree produced by JavaParser#nonWildcardTypeArguments.
    def exitNonWildcardTypeArguments(self, ctx:JavaParser.NonWildcardTypeArgumentsContext):
        pass


    # Enter a parse tree produced by JavaParser#typeList.
    def enterTypeList(self, ctx:JavaParser.TypeListContext):
        pass

    # Exit a parse tree produced by JavaParser#typeList.
    def exitTypeList(self, ctx:JavaParser.TypeListContext):
        pass


    # Enter a parse tree produced by JavaParser#typeType.
    def enterTypeType(self, ctx:JavaParser.TypeTypeContext):
        pass

    # Exit a parse tree produced by JavaParser#typeType.
    def exitTypeType(self, ctx:JavaParser.TypeTypeContext):
        pass


    # Enter a parse tree produced by JavaParser#primitiveType.
    def enterPrimitiveType(self, ctx:JavaParser.PrimitiveTypeContext):
        pass

    # Exit a parse tree produced by JavaParser#primitiveType.
    def exitPrimitiveType(self, ctx:JavaParser.PrimitiveTypeContext):
        pass


    # Enter a parse tree produced by JavaParser#typeArguments.
    def enterTypeArguments(self, ctx:JavaParser.TypeArgumentsContext):
        pass

    # Exit a parse tree produced by JavaParser#typeArguments.
    def exitTypeArguments(self, ctx:JavaParser.TypeArgumentsContext):
        pass


    # Enter a parse tree produced by JavaParser#superSuffix.
    def enterSuperSuffix(self, ctx:JavaParser.SuperSuffixContext):
        pass

    # Exit a parse tree produced by JavaParser#superSuffix.
    def exitSuperSuffix(self, ctx:JavaParser.SuperSuffixContext):
        pass


    # Enter a parse tree produced by JavaParser#explicitGenericInvocationSuffix.
    def enterExplicitGenericInvocationSuffix(self, ctx:JavaParser.ExplicitGenericInvocationSuffixContext):
        pass

    # Exit a parse tree produced by JavaParser#explicitGenericInvocationSuffix.
    def exitExplicitGenericInvocationSuffix(self, ctx:JavaParser.ExplicitGenericInvocationSuffixContext):
        pass


    # Enter a parse tree produced by JavaParser#arguments.
    def enterArguments(self, ctx:JavaParser.ArgumentsContext):
        pass

    # Exit a parse tree produced by JavaParser#arguments.
    def exitArguments(self, ctx:JavaParser.ArgumentsContext):
        pass



del JavaParser