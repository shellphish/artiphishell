# Generated from JavaParser.g4 by ANTLR 4.13.2
from antlr4 import *
if "." in __name__:
    from .JavaParser import JavaParser
else:
    from JavaParser import JavaParser

# This class defines a complete generic visitor for a parse tree produced by JavaParser.

class JavaParserVisitor(ParseTreeVisitor):

    # Visit a parse tree produced by JavaParser#compilationUnit.
    def visitCompilationUnit(self, ctx:JavaParser.CompilationUnitContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#packageDeclaration.
    def visitPackageDeclaration(self, ctx:JavaParser.PackageDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#importDeclaration.
    def visitImportDeclaration(self, ctx:JavaParser.ImportDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#typeDeclaration.
    def visitTypeDeclaration(self, ctx:JavaParser.TypeDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#modifier.
    def visitModifier(self, ctx:JavaParser.ModifierContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#classOrInterfaceModifier.
    def visitClassOrInterfaceModifier(self, ctx:JavaParser.ClassOrInterfaceModifierContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#variableModifier.
    def visitVariableModifier(self, ctx:JavaParser.VariableModifierContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#classDeclaration.
    def visitClassDeclaration(self, ctx:JavaParser.ClassDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#typeParameters.
    def visitTypeParameters(self, ctx:JavaParser.TypeParametersContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#typeParameter.
    def visitTypeParameter(self, ctx:JavaParser.TypeParameterContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#typeBound.
    def visitTypeBound(self, ctx:JavaParser.TypeBoundContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#enumDeclaration.
    def visitEnumDeclaration(self, ctx:JavaParser.EnumDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#enumConstants.
    def visitEnumConstants(self, ctx:JavaParser.EnumConstantsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#enumConstant.
    def visitEnumConstant(self, ctx:JavaParser.EnumConstantContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#enumBodyDeclarations.
    def visitEnumBodyDeclarations(self, ctx:JavaParser.EnumBodyDeclarationsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#interfaceDeclaration.
    def visitInterfaceDeclaration(self, ctx:JavaParser.InterfaceDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#classBody.
    def visitClassBody(self, ctx:JavaParser.ClassBodyContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#interfaceBody.
    def visitInterfaceBody(self, ctx:JavaParser.InterfaceBodyContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#classBodyDeclaration.
    def visitClassBodyDeclaration(self, ctx:JavaParser.ClassBodyDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#memberDeclaration.
    def visitMemberDeclaration(self, ctx:JavaParser.MemberDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#methodDeclaration.
    def visitMethodDeclaration(self, ctx:JavaParser.MethodDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#methodBody.
    def visitMethodBody(self, ctx:JavaParser.MethodBodyContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#typeTypeOrVoid.
    def visitTypeTypeOrVoid(self, ctx:JavaParser.TypeTypeOrVoidContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#genericMethodDeclaration.
    def visitGenericMethodDeclaration(self, ctx:JavaParser.GenericMethodDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#genericConstructorDeclaration.
    def visitGenericConstructorDeclaration(self, ctx:JavaParser.GenericConstructorDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#constructorDeclaration.
    def visitConstructorDeclaration(self, ctx:JavaParser.ConstructorDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#compactConstructorDeclaration.
    def visitCompactConstructorDeclaration(self, ctx:JavaParser.CompactConstructorDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#fieldDeclaration.
    def visitFieldDeclaration(self, ctx:JavaParser.FieldDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#interfaceBodyDeclaration.
    def visitInterfaceBodyDeclaration(self, ctx:JavaParser.InterfaceBodyDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#interfaceMemberDeclaration.
    def visitInterfaceMemberDeclaration(self, ctx:JavaParser.InterfaceMemberDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#constDeclaration.
    def visitConstDeclaration(self, ctx:JavaParser.ConstDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#constantDeclarator.
    def visitConstantDeclarator(self, ctx:JavaParser.ConstantDeclaratorContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#interfaceMethodDeclaration.
    def visitInterfaceMethodDeclaration(self, ctx:JavaParser.InterfaceMethodDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#interfaceMethodModifier.
    def visitInterfaceMethodModifier(self, ctx:JavaParser.InterfaceMethodModifierContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#genericInterfaceMethodDeclaration.
    def visitGenericInterfaceMethodDeclaration(self, ctx:JavaParser.GenericInterfaceMethodDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#interfaceCommonBodyDeclaration.
    def visitInterfaceCommonBodyDeclaration(self, ctx:JavaParser.InterfaceCommonBodyDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#variableDeclarators.
    def visitVariableDeclarators(self, ctx:JavaParser.VariableDeclaratorsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#variableDeclarator.
    def visitVariableDeclarator(self, ctx:JavaParser.VariableDeclaratorContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#variableDeclaratorId.
    def visitVariableDeclaratorId(self, ctx:JavaParser.VariableDeclaratorIdContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#variableInitializer.
    def visitVariableInitializer(self, ctx:JavaParser.VariableInitializerContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#arrayInitializer.
    def visitArrayInitializer(self, ctx:JavaParser.ArrayInitializerContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#classOrInterfaceType.
    def visitClassOrInterfaceType(self, ctx:JavaParser.ClassOrInterfaceTypeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#typeArgument.
    def visitTypeArgument(self, ctx:JavaParser.TypeArgumentContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#qualifiedNameList.
    def visitQualifiedNameList(self, ctx:JavaParser.QualifiedNameListContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#formalParameters.
    def visitFormalParameters(self, ctx:JavaParser.FormalParametersContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#receiverParameter.
    def visitReceiverParameter(self, ctx:JavaParser.ReceiverParameterContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#formalParameterList.
    def visitFormalParameterList(self, ctx:JavaParser.FormalParameterListContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#formalParameter.
    def visitFormalParameter(self, ctx:JavaParser.FormalParameterContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#lastFormalParameter.
    def visitLastFormalParameter(self, ctx:JavaParser.LastFormalParameterContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#lambdaLVTIList.
    def visitLambdaLVTIList(self, ctx:JavaParser.LambdaLVTIListContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#lambdaLVTIParameter.
    def visitLambdaLVTIParameter(self, ctx:JavaParser.LambdaLVTIParameterContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#qualifiedName.
    def visitQualifiedName(self, ctx:JavaParser.QualifiedNameContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#literal.
    def visitLiteral(self, ctx:JavaParser.LiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#integerLiteral.
    def visitIntegerLiteral(self, ctx:JavaParser.IntegerLiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#floatLiteral.
    def visitFloatLiteral(self, ctx:JavaParser.FloatLiteralContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#altAnnotationQualifiedName.
    def visitAltAnnotationQualifiedName(self, ctx:JavaParser.AltAnnotationQualifiedNameContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#annotation.
    def visitAnnotation(self, ctx:JavaParser.AnnotationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#elementValuePairs.
    def visitElementValuePairs(self, ctx:JavaParser.ElementValuePairsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#elementValuePair.
    def visitElementValuePair(self, ctx:JavaParser.ElementValuePairContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#elementValue.
    def visitElementValue(self, ctx:JavaParser.ElementValueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#elementValueArrayInitializer.
    def visitElementValueArrayInitializer(self, ctx:JavaParser.ElementValueArrayInitializerContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#annotationTypeDeclaration.
    def visitAnnotationTypeDeclaration(self, ctx:JavaParser.AnnotationTypeDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#annotationTypeBody.
    def visitAnnotationTypeBody(self, ctx:JavaParser.AnnotationTypeBodyContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#annotationTypeElementDeclaration.
    def visitAnnotationTypeElementDeclaration(self, ctx:JavaParser.AnnotationTypeElementDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#annotationTypeElementRest.
    def visitAnnotationTypeElementRest(self, ctx:JavaParser.AnnotationTypeElementRestContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#annotationMethodOrConstantRest.
    def visitAnnotationMethodOrConstantRest(self, ctx:JavaParser.AnnotationMethodOrConstantRestContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#annotationMethodRest.
    def visitAnnotationMethodRest(self, ctx:JavaParser.AnnotationMethodRestContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#annotationConstantRest.
    def visitAnnotationConstantRest(self, ctx:JavaParser.AnnotationConstantRestContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#defaultValue.
    def visitDefaultValue(self, ctx:JavaParser.DefaultValueContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#moduleDeclaration.
    def visitModuleDeclaration(self, ctx:JavaParser.ModuleDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#moduleBody.
    def visitModuleBody(self, ctx:JavaParser.ModuleBodyContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#moduleDirective.
    def visitModuleDirective(self, ctx:JavaParser.ModuleDirectiveContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#requiresModifier.
    def visitRequiresModifier(self, ctx:JavaParser.RequiresModifierContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#recordDeclaration.
    def visitRecordDeclaration(self, ctx:JavaParser.RecordDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#recordHeader.
    def visitRecordHeader(self, ctx:JavaParser.RecordHeaderContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#recordComponentList.
    def visitRecordComponentList(self, ctx:JavaParser.RecordComponentListContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#recordComponent.
    def visitRecordComponent(self, ctx:JavaParser.RecordComponentContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#recordBody.
    def visitRecordBody(self, ctx:JavaParser.RecordBodyContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#block.
    def visitBlock(self, ctx:JavaParser.BlockContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#blockStatement.
    def visitBlockStatement(self, ctx:JavaParser.BlockStatementContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#localVariableDeclaration.
    def visitLocalVariableDeclaration(self, ctx:JavaParser.LocalVariableDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#identifier.
    def visitIdentifier(self, ctx:JavaParser.IdentifierContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#typeIdentifier.
    def visitTypeIdentifier(self, ctx:JavaParser.TypeIdentifierContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#localTypeDeclaration.
    def visitLocalTypeDeclaration(self, ctx:JavaParser.LocalTypeDeclarationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#statement.
    def visitStatement(self, ctx:JavaParser.StatementContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#catchClause.
    def visitCatchClause(self, ctx:JavaParser.CatchClauseContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#catchType.
    def visitCatchType(self, ctx:JavaParser.CatchTypeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#finallyBlock.
    def visitFinallyBlock(self, ctx:JavaParser.FinallyBlockContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#resourceSpecification.
    def visitResourceSpecification(self, ctx:JavaParser.ResourceSpecificationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#resources.
    def visitResources(self, ctx:JavaParser.ResourcesContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#resource.
    def visitResource(self, ctx:JavaParser.ResourceContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#switchBlockStatementGroup.
    def visitSwitchBlockStatementGroup(self, ctx:JavaParser.SwitchBlockStatementGroupContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#switchLabel.
    def visitSwitchLabel(self, ctx:JavaParser.SwitchLabelContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#forControl.
    def visitForControl(self, ctx:JavaParser.ForControlContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#forInit.
    def visitForInit(self, ctx:JavaParser.ForInitContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#enhancedForControl.
    def visitEnhancedForControl(self, ctx:JavaParser.EnhancedForControlContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#parExpression.
    def visitParExpression(self, ctx:JavaParser.ParExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#expressionList.
    def visitExpressionList(self, ctx:JavaParser.ExpressionListContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#methodCall.
    def visitMethodCall(self, ctx:JavaParser.MethodCallContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#TernaryExpression.
    def visitTernaryExpression(self, ctx:JavaParser.TernaryExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#InstanceOfOperatorExpression.
    def visitInstanceOfOperatorExpression(self, ctx:JavaParser.InstanceOfOperatorExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#UnaryOperatorExpression.
    def visitUnaryOperatorExpression(self, ctx:JavaParser.UnaryOperatorExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#PrimaryExpression.
    def visitPrimaryExpression(self, ctx:JavaParser.PrimaryExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#ObjectCreationExpression.
    def visitObjectCreationExpression(self, ctx:JavaParser.ObjectCreationExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#ExpressionLambda.
    def visitExpressionLambda(self, ctx:JavaParser.ExpressionLambdaContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#PostIncrementDecrementOperatorExpression.
    def visitPostIncrementDecrementOperatorExpression(self, ctx:JavaParser.PostIncrementDecrementOperatorExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#MemberReferenceExpression.
    def visitMemberReferenceExpression(self, ctx:JavaParser.MemberReferenceExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#ExpressionSwitch.
    def visitExpressionSwitch(self, ctx:JavaParser.ExpressionSwitchContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#BinaryOperatorExpression.
    def visitBinaryOperatorExpression(self, ctx:JavaParser.BinaryOperatorExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#MethodCallExpression.
    def visitMethodCallExpression(self, ctx:JavaParser.MethodCallExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#MethodReferenceExpression.
    def visitMethodReferenceExpression(self, ctx:JavaParser.MethodReferenceExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#SquareBracketExpression.
    def visitSquareBracketExpression(self, ctx:JavaParser.SquareBracketExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#CastExpression.
    def visitCastExpression(self, ctx:JavaParser.CastExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#pattern.
    def visitPattern(self, ctx:JavaParser.PatternContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#lambdaExpression.
    def visitLambdaExpression(self, ctx:JavaParser.LambdaExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#lambdaParameters.
    def visitLambdaParameters(self, ctx:JavaParser.LambdaParametersContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#lambdaBody.
    def visitLambdaBody(self, ctx:JavaParser.LambdaBodyContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#primary.
    def visitPrimary(self, ctx:JavaParser.PrimaryContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#switchExpression.
    def visitSwitchExpression(self, ctx:JavaParser.SwitchExpressionContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#switchLabeledRule.
    def visitSwitchLabeledRule(self, ctx:JavaParser.SwitchLabeledRuleContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#guardedPattern.
    def visitGuardedPattern(self, ctx:JavaParser.GuardedPatternContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#switchRuleOutcome.
    def visitSwitchRuleOutcome(self, ctx:JavaParser.SwitchRuleOutcomeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#classType.
    def visitClassType(self, ctx:JavaParser.ClassTypeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#creator.
    def visitCreator(self, ctx:JavaParser.CreatorContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#createdName.
    def visitCreatedName(self, ctx:JavaParser.CreatedNameContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#innerCreator.
    def visitInnerCreator(self, ctx:JavaParser.InnerCreatorContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#arrayCreatorRest.
    def visitArrayCreatorRest(self, ctx:JavaParser.ArrayCreatorRestContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#classCreatorRest.
    def visitClassCreatorRest(self, ctx:JavaParser.ClassCreatorRestContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#explicitGenericInvocation.
    def visitExplicitGenericInvocation(self, ctx:JavaParser.ExplicitGenericInvocationContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#typeArgumentsOrDiamond.
    def visitTypeArgumentsOrDiamond(self, ctx:JavaParser.TypeArgumentsOrDiamondContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#nonWildcardTypeArgumentsOrDiamond.
    def visitNonWildcardTypeArgumentsOrDiamond(self, ctx:JavaParser.NonWildcardTypeArgumentsOrDiamondContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#nonWildcardTypeArguments.
    def visitNonWildcardTypeArguments(self, ctx:JavaParser.NonWildcardTypeArgumentsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#typeList.
    def visitTypeList(self, ctx:JavaParser.TypeListContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#typeType.
    def visitTypeType(self, ctx:JavaParser.TypeTypeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#primitiveType.
    def visitPrimitiveType(self, ctx:JavaParser.PrimitiveTypeContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#typeArguments.
    def visitTypeArguments(self, ctx:JavaParser.TypeArgumentsContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#superSuffix.
    def visitSuperSuffix(self, ctx:JavaParser.SuperSuffixContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#explicitGenericInvocationSuffix.
    def visitExplicitGenericInvocationSuffix(self, ctx:JavaParser.ExplicitGenericInvocationSuffixContext):
        return self.visitChildren(ctx)


    # Visit a parse tree produced by JavaParser#arguments.
    def visitArguments(self, ctx:JavaParser.ArgumentsContext):
        return self.visitChildren(ctx)



del JavaParser